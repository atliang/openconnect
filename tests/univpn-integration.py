#!/usr/bin/env python3
"""Exercise the real native client against a loopback-only mock TLS gateway.
No root/TUN device, remote server or private configuration is needed.
Run: python3 tests/univpn-integration.py [path-to-openconnect]
"""
import os
import pathlib
import shlex
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = str(pathlib.Path(sys.argv.pop(1) if len(sys.argv) > 1 else './openconnect').resolve())
MAGIC = bytes.fromhex('c192a4d601')
TOKEN = bytes(range(32))
assert len(TOKEN) == 32

def exact(sock, size):
    result = b''
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError()
        result += part
    return result

def frame(cmd, body=b''):
    return MAGIC + struct.pack('!BH', cmd, len(body)) + body

def receive(sock):
    header = exact(sock, 8)
    if header[:5] != MAGIC:
        raise ValueError('bad header')
    return header[5], exact(sock, struct.unpack('!H', header[6:])[0])

def tlv(kind, value):
    return struct.pack('!HH', kind, len(value)) + value

class Gateway:
    def __init__(self, ctx, auth_ok=True, malformed=False, data_ctx=None):
        self.ctx, self.auth_ok, self.malformed = ctx, auth_ok, malformed
        self.data_ctx, self.count = data_ctx, 0
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen()
        self.listener.settimeout(.2)
        self.stop = threading.Event()
        self.sockets, self.errors, self.received = [], [], []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()
    def accept(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.sockets.append(raw)
            ctx = self.data_ctx if self.count and self.data_ctx else self.ctx
            self.count += 1
            threading.Thread(target=self.handle, args=(raw,ctx), daemon=True).start()
    def send(self, sock, cmd, body):
        # Header/body fragmentation also exercises handshake buffering.
        data = frame(cmd, body)
        if cmd == 0x66:
            sock.sendall(data)
            return
        for part in (data[:3], data[3:7], data[7:9], data[9:]):
            if part:
                sock.sendall(part)
                time.sleep(.005)
    def handle(self, raw, ctx):
        try:
            with ctx.wrap_socket(raw, server_side=True) as sock:
                self.sockets.append(sock)
                sock.settimeout(30)
                first = exact(sock, 8)
                if first[:4] == bytes.fromhex('fefcefbe'):
                    first += exact(sock, 332)
                    assert len(first) == 340 and first[80:89] == b'localhost'
                    self.send(sock, 0, b'\0'*4)
                    cmd, auth = receive(sock)
                    assert cmd == 1 and auth[:9] == b'localhost'
                    assert b'mockuser\0' in auth and b'mock%26%2B%25pass\0' in auth
                    self.send(sock, 1, struct.pack('!II', 0 if self.auth_ok else 1, 0) + tlv(3, TOKEN))
                    if not self.auth_ok:
                        return
                    cmd, body = receive(sock)
                    assert cmd == 3 and body == TOKEN
                    self.send(sock, 3, b'\0'*4 + tlv(1, socket.inet_aton('10.90.0.2') + b'\x20') +
                              tlv(6, socket.inet_aton('198.51.100.0') + b'\x18'))
                    while True:
                        cmd, body = receive(sock)
                        assert cmd == 6 and body[:32] == TOKEN and len(body) == 36
                        self.send(sock, 6, b'')
                else:
                    assert first[:5] == MAGIC and first[5] == 0x64
                    assert exact(sock, 32) == TOKEN
                    self.send(sock, 0x64, b'\0')
                    if self.malformed:
                        sock.sendall(b'WRONGHDR')
                        time.sleep(.2)
                        return
                    while True:
                        cmd, body = receive(sock)
                        if cmd == 0x65:
                            self.send(sock, cmd, b'')
                        else:
                            assert cmd == 0x66 and body[:8] == b'\0'*8
                            self.received.append(body[8:])
                            self.send(sock, cmd, body)
        except (EOFError, OSError, ssl.SSLError):
            pass
        except Exception as exc:
            self.errors.append(str(exc))
    def close(self):
        self.stop.set()
        self.listener.close()
        for sock in self.sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.thread.join(1)

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='univpn-mock-')
        cls.root = pathlib.Path(cls.tmp.name)
        cls.cert, cls.key = cls.root/'server.pem', cls.root/'server.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost',
                        '-keyout',str(cls.key),'-out',str(cls.cert)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.ctx.load_cert_chain(cls.cert, cls.key)
    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
    def run_client(self, gateway, packet_test=False, cafile=True):
        report = self.root/'result'
        report.unlink(missing_ok=True)
        script = self.root/'packet.py'
        script.write_text('''import os, socket, struct, time, pathlib
s=socket.socket(fileno=int(os.environ["VPNFD"]))
s.settimeout(8)
for proto in (6,17,1):
    packet=struct.pack("!BBHHHBBH4s4s",0x45,0,36,1,0,64,proto,0,socket.inet_aton("10.90.0.2"),socket.inet_aton("198.51.100.1"))+b"0123456789abcdef"
    s.send(packet)
    assert s.recv(65535)==packet
pathlib.Path(os.environ["MOCK_REPORT"]).write_text("PASS")
time.sleep(60)
''')
        cmd = [BINARY, '--no-proxy', '--verbose', '--protocol=univpn','--non-inter','--user=mockuser','--passwd-on-stdin',
               '--authgroup=localhost','--no-dtls','https://127.0.0.1:'+str(gateway.port)]
        if cafile:
            cmd += ['--cafile='+str(self.cert)]
        if packet_test:
            cmd += ['--script-tun','--script', shlex.quote(sys.executable)+' '+shlex.quote(str(script))]
        else:
            cmd += ['--authenticate']
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={**os.environ,'MOCK_REPORT':str(report)})
        proc.stdin.write(b'mock&+%pass\n'); proc.stdin.close(); proc.stdin = None
        try:
            if packet_test:
                end = time.monotonic()+15
                while time.monotonic()<end and proc.poll() is None and not report.exists():
                    time.sleep(.05)
                passed = report.exists()
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                out, err = proc.communicate(timeout=8)
                return passed, proc.returncode, 'exit='+str(proc.returncode)+'\n'+out.decode(errors='replace')+err.decode(errors='replace')
            out, err = proc.communicate(timeout=40)
            return False, proc.returncode, 'exit='+str(proc.returncode)+'\n'+out.decode(errors='replace')+err.decode(errors='replace')
        finally:
            if proc.poll() is None:
                proc.kill(); proc.communicate()
    def test_ipv4_tcp_udp_icmp_frames(self):
        gateway = Gateway(self.ctx)
        try:
            passed, _, err = self.run_client(gateway, packet_test=True)
            self.assertTrue(passed, err)
            self.assertEqual([p[9] for p in gateway.received], [6,17,1])
            self.assertEqual(gateway.errors, [])
        finally:
            gateway.close()
    def test_authentication_success(self):
        gateway = Gateway(self.ctx)
        try:
            _, code, err = self.run_client(gateway)
            self.assertEqual(code, 0, err)
            self.assertEqual(gateway.errors, [])
        finally:
            gateway.close()
    def test_authentication_rejected(self):
        gateway = Gateway(self.ctx, auth_ok=False)
        try:
            _, code, err = self.run_client(gateway)
            self.assertEqual(code, 1)
            self.assertNotIn('mock&+%pass', err)
            self.assertNotIn('AddressSanitizer', err)
            self.assertEqual(gateway.errors, [])
        finally:
            gateway.close()
    def test_untrusted_certificate_rejected(self):
        gateway = Gateway(self.ctx)
        try:
            _, code, _ = self.run_client(gateway, cafile=False)
            self.assertEqual(code, 1)
            self.assertEqual(gateway.received, [])
        finally:
            gateway.close()
    def test_data_channel_must_match_control_identity(self):
        second_cert, second_key = self.root/'second.pem', self.root/'second.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                        '-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost',
                        '-keyout',str(second_key),'-out',str(second_cert)],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        second_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        second_ctx.load_cert_chain(second_cert,second_key)
        bundle = self.root/'both-trusted.pem'
        bundle.write_bytes(self.cert.read_bytes()+second_cert.read_bytes())
        gateway = Gateway(self.ctx,data_ctx=second_ctx)
        original_cert = self.cert; self.cert = bundle
        try:
            passed, code, err = self.run_client(gateway,packet_test=True)
            self.assertFalse(passed)
            self.assertEqual(code,2,err)
            self.assertEqual(gateway.received,[])
            self.assertNotIn('AddressSanitizer',err)
        finally:
            self.cert = original_cert; gateway.close()
    def test_malformed_data_frame_terminates(self):
        gateway = Gateway(self.ctx, malformed=True)
        try:
            passed, code, err = self.run_client(gateway, packet_test=True)
            self.assertFalse(passed)
            self.assertEqual(code, 1)
            self.assertIn('invalid frame', err)
        finally:
            gateway.close()

if __name__ == '__main__':
    unittest.main(verbosity=2)
