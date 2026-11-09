#!/usr/bin/env python3
#
# Copyright © 2026 Brice McIver
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

########################################
# This program emulates the authentication-phase and configuration-phase
# behavior of a SonicWall NetExtender server enough to test OpenConnect's
# behavior against it. Specifically, it emulates the following requests:
#
#    POST /cgi-bin/userLogin (username, password, domain, login=true)
#      No 2FA)        Sets the 'swap' cookie
#      OTP 2FA)       Sets the 'swap' cookie, with X-NE-tf: 1
#      Challenge 2FA) Returns X-NE-tf: 5 and X-NE-rsastate (no cookie)
#    POST /cgi-bin/userLogin (radiusReply, pstate, state=RADIUSCHALLENGE, ...)
#    POST /cgi-bin/otpLogin (password)
#    GET /cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=...
#    CONNECT localhost:0
#    POST /cgi-bin/userLogout
#
# Quirks of real servers which are reproduced here:
#  - Login responses have no body; everything is in X-NE-* headers.
#  - The configuration is wrapped in HTML/JavaScript, and some lines
#    end with ';'.
#  - The configuration response re-issues the 'swap' cookie with its
#    base64-DECODED value, which the client must ignore.
#  - The tunnel CONNECT request carries the decoded cookie value in
#    Proxy-Authorization. Since Flask can't speak PPP, a correct CONNECT
#    request gets 407 (which OpenConnect treats as "cookie rejected"),
#    and an incorrect one gets 500.
#
# GET /STATUS reports whether the last CONNECT and logout were correct.
########################################

import sys
import ssl
import base64
from flask import Flask, request, make_response
from dataclasses import dataclass

host, port, *cert_and_maybe_keyfile = sys.argv[1:]

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(*cert_and_maybe_keyfile)

app = Flask(__name__)
app.config.update(DEBUG=True, HOST=host, PORT=int(port))

SESSION_ID = '49a5ccc0fakesess'
SWAP = base64.b64encode(SESSION_ID.encode()).decode()
USERNAME, PASSWORD = 'test', 'test'
DOMAIN = 'LocalDomain'
CHALLENGE_STATE = 'PS+1/x='
CHALLENGE_REPLY = '4242'


########################################

# Configure the fake server. These settings will persist unless/until reconfigured or restarted:
#   type_2fa: 2FA type ('otp', 'challenge', or None)
#   ppp: PPP mode the server asks for ('async' or 'sync')
#   tunnel_all: Server requests that all traffic be tunneled
@dataclass
class TestConfiguration:
    type_2fa: str = None
    ppp: str = 'async'
    tunnel_all: bool = False
C = TestConfiguration()


@dataclass
class Status:
    connect: str = 'none'
    logout: str = 'none'
S = Status()


@app.route('/CONFIGURE', methods=('POST', 'GET'))
def configure():
    global C, S
    if request.method == 'POST':
        C = TestConfiguration(
            type_2fa=request.form.get('type_2fa') or None,
            ppp=request.form.get('ppp', 'async'),
            tunnel_all=bool(int(request.form.get('tunnel_all', 0))))
        S = Status()
        return '', 201
    else:
        return 'Current configuration of fake NetExtender server:\n{}\n'.format(C)


@app.route('/STATUS')
def status():
    return 'connect={} logout={}\n'.format(S.connect, S.logout)


def x_ne(status=200, **headers):
    resp = make_response('', status)
    for k, v in headers.items():
        resp.headers['X-NE-' + k] = str(v)
    return resp


def issue_cookie(resp):
    resp.headers.add('Set-Cookie', 'swap={}; path=/;'.format(SWAP))
    return resp


@app.route('/cgi-bin/userLogin', methods=['POST'])
def login():
    f = request.form
    if f.get('domain') != DOMAIN or f.get('username') != USERNAME:
        return x_ne(message='Invalid domain or username')

    if f.get('state') == 'RADIUSCHALLENGE':
        if C.type_2fa == 'challenge' and f.get('pstate') == CHALLENGE_STATE and f.get('radiusReply') == CHALLENGE_REPLY:
            return issue_cookie(x_ne(tf=0, tfresult=0))
        return x_ne(message='Challenge failed', tfresult=2)

    if f.get('login') != 'true' or f.get('password') != PASSWORD:
        return x_ne(message='Invalid username or password')

    if C.type_2fa == 'challenge':
        return x_ne(tf=5, message='Enter the PIN', rsastate=CHALLENGE_STATE)
    elif C.type_2fa == 'otp':
        return issue_cookie(x_ne(tf=1, message='A one-time password was sent to your email'))
    else:
        return issue_cookie(x_ne(tfresult=0, pwdexpdays=12))


@app.route('/cgi-bin/otpLogin', methods=['POST'])
def otp_login():
    if request.cookies.get('swap') != SWAP:
        return x_ne(403)
    code = request.form.get('password', '')
    if len(code) == 6 and code.isdigit() and code != '000000':
        return x_ne(tfresult=0)
    return x_ne(tfresult=1, message='Invalid code; try again')


@app.route('/cgi-bin/sslvpnclient')
def sslvpnclient():
    a = request.args
    assert a.get('launchplatform') == 'mac' and a.get('neProto') == '3' and a.get('supportipv6') in ('yes', 'no'), \
        'unexpected query {!r}'.format(a)
    if request.cookies.get('swap') != SWAP:
        return x_ne(error=1, message='Session expired')

    lines = [
        "<html><head><title>SonicWALL - Virtual Office</title><script>function neLauncherInit(){",
        'NELaunchX1.userName = "{}";'.format(USERNAME),
        'NELaunchX1.domainName = "{}";'.format(DOMAIN),
        'SessionId = QkMO6MFoLUdjNiCNLyakRw==;',
        'Route = 10.10.0.0/255.255.0.0',
        'Route = 192.168.5.0/24',
        'dns1 = 10.0.0.53',
        'dns2 = 0.0.0.0',
        'dnsSuffixes = corp.example',
        'ipv6Support = no',
        'pppFrameEncoded = 0;',
        'PppPref = {}'.format(C.ppp),
        'TunnelAllMode = {};'.format(int(C.tunnel_all)),
        'AllowSavePassword = 1;',
        'ClientIPLower = "10.0.0.2";',
        '}</script></head></html>',
    ]
    resp = make_response('\n'.join(lines))
    # The client must IGNORE this (decoded) replacement cookie
    resp.headers.add('Set-Cookie', 'swap={}; path=/;'.format(SESSION_ID))
    return resp


@app.before_request
def tunnel():
    if request.method != 'CONNECT':
        return None

    h = request.headers
    errors = []
    if h.get('Proxy-Authorization') != SESSION_ID:
        errors.append('Proxy-Authorization {!r}'.format(h.get('Proxy-Authorization')))
    if ('Connection-Medium' in h) != (C.ppp == 'async'):
        errors.append('Connection-Medium {!r} with PPP {}'.format(h.get('Connection-Medium'), C.ppp))
    for k, v in (('X-SSLVPN-SERVICE', 'NETEXTENDER'), ('X-SSLVPN-PROTOCOL', '2.0'),
                 ('X-NE-PROTOCOL', '2.0'), ('Frame-Encode', 'off'), ('X-NX-Client-Platform', 'Linux')):
        if h.get(k) != v:
            errors.append('{} {!r}'.format(k, h.get(k)))

    S.connect = 'bad:' + ','.join(errors) if errors else 'ok'
    # Flask can't speak PPP. 407 is what a real server sends for a bad
    # session, so OpenConnect treats it as a rejected cookie.
    return make_response(S.connect, 500 if errors else 407)


@app.route('/cgi-bin/userLogout', methods=['POST'])
def logout():
    S.logout = 'ok' if request.cookies.get('swap') == SWAP else 'bad:{!r}'.format(request.cookies.get('swap'))
    return ''


app.run(host=app.config['HOST'], port=app.config['PORT'], debug=app.config['DEBUG'],
        ssl_context=context, use_debugger=False)
