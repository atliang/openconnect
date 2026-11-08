/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2026 Brice McIver
 *
 * Author: Brice McIver <brice@bricemciver.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

/*
 * SonicWall NetExtender SSL VPN.
 *
 * Protocol, as observed in the official Linux client (netExtender 10.2.816):
 *
 * 1. Login:  POST /cgi-bin/userLogin
 *              username=…&password=…&domain=…&login=true
 *    On success the server sets a base64-encoded 'swap' cookie. Status is
 *    signalled through X-NE-* response headers:
 *      X-NE-tf:         two-factor scheme (0 none, 1 OTP, 2 RSA new PIN,
 *                       3 RSA system PIN, 4 RSA next token, 5 RADIUS challenge)
 *      X-NE-tfresult:   two-factor result (0 OK, 1 retry, 2/3 failed)
 *      X-NE-message:    prompt or error text
 *      X-NE-rsastate:   opaque state to echo back as 'pstate'
 *      X-NE-pwdexpdays: days to password expiry (<0: must change now)
 *      X-NE-saml:       "authType:SAML" if SAML login is required
 *    OTP is then submitted to POST /cgi-bin/otpLogin (password=…), while
 *    challenges are answered with another POST to /cgi-bin/userLogin.
 *
 * 2. Config: GET /cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=…
 *    with the 'swap' cookie. Body contains "Key = Value" lines (SessionId,
 *    Route, Ipv6Route, dns1, dns2, dnsSuffixes, TunnelAllMode, PppPref, …).
 *    X-NE-error: non-zero indicates failure.
 *
 * 3. Tunnel: on a fresh TLS connection, send
 *      CONNECT localhost:0 HTTP/1.0
 *      X-SSLVPN-PROTOCOL: 2.0
 *      X-SSLVPN-SERVICE: NETEXTENDER
 *      Proxy-Authorization:<base64-DECODED swap cookie>
 *      X-NX-Client-Platform: Linux
 *      Connection-Medium: MacOS            (only in async PPP mode)
 *      User-Agent: …
 *      Frame-Encode: off                   (only when pppFrameEncoded=0)
 *      X-NE-PROTOCOL: 2.0                  (only when pppFrameEncoded=0)
 *    No response is sent on success; PPP frames follow, each preceded by a
 *    4-byte big-endian length. In sync mode each one is a raw PPP frame;
 *    in async mode it is part of an RFC1662 HDLC byte stream. An HTTP
 *    response (e.g. 407) indicates failure.
 *
 * 4. Logout: POST /cgi-bin/userLogout with the 'swap' cookie.
 */

#include <config.h>

#include "openconnect-internal.h"

#include "ppp.h"

#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#define NX_USER_AGENT		"SonicWALL NetExtender for Linux 10.2.816"
#define NX_DEFAULT_DOMAIN	"LocalDomain"
#define NX_COOKIE		"swap"

/* X-NE-tf values */
#define NX_TF_NONE		0
#define NX_TF_OTP		1
#define NX_TF_RSA_NEWPIN	2
#define NX_TF_RSA_SYSPIN	3
#define NX_TF_RSA_NEXTTOKEN	4
#define NX_TF_CHALLENGE		5

/* Give up after this many rejected codes / challenge rounds, so that a
 * saved --form-entry value can't make us retry forever. */
#define NX_MAX_ATTEMPTS		5

/* X-NE-tfresult values */
#define NX_TFRESULT_OK		0
#define NX_TFRESULT_RETRY	1

void netextender_common_headers(struct openconnect_info *vpninfo,
				struct oc_text_buf *buf)
{
	char *orig_ua = vpninfo->useragent;

	vpninfo->useragent = (char *)NX_USER_AGENT;
	http_common_headers(vpninfo, buf);
	vpninfo->useragent = orig_ua;

	buf_append(buf, "Cache-Control: no-cache\r\n");
	buf_append(buf, "X-NE-pda: true\r\n");
}

/* Collect X-NE-* headers so that the caller can inspect them */
static int nx_header_cb(struct openconnect_info *vpninfo, char *hdr, char *val)
{
	if (!strncasecmp(hdr, "X-NE-", 5))
		add_option_dup(&vpninfo->nx_resp_hdrs, hdr, val, -1);

	return http_auth_hdrs(vpninfo, hdr, val);
}

static const char *nx_hdr(struct openconnect_info *vpninfo, const char *name)
{
	struct oc_vpn_option *h;

	for (h = vpninfo->nx_resp_hdrs; h; h = h->next)
		if (!strcasecmp(h->option, name))
			return h->value;
	return NULL;
}

static int nx_hdr_int(struct openconnect_info *vpninfo, const char *name, int def)
{
	const char *val = nx_hdr(vpninfo, name);

	return (val && *val) ? atoi(val) : def;
}

static int nx_request(struct openconnect_info *vpninfo, const char *method,
		      const char *path, struct oc_text_buf *body, char **resp_buf)
{
	free_optlist(vpninfo->nx_resp_hdrs);
	vpninfo->nx_resp_hdrs = NULL;

	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup(path);
	if (!vpninfo->urlpath)
		return -ENOMEM;

	return do_https_request(vpninfo, method,
				body ? "application/x-www-form-urlencoded" : NULL,
				body, resp_buf, nx_header_cb,
				HTTP_BODY_ON_ERROR | HTTP_EMPTY_BODY_OK);
}

static const char *nx_cookie_value(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *c;

	for (c = vpninfo->cookies; c; c = c->next)
		if (!strcmp(c->option, NX_COOKIE) && c->value && *c->value)
			return c->value;
	return NULL;
}

static struct oc_form_opt *nx_add_opt(struct oc_auth_form *form, int type,
				      const char *name, const char *label,
				      const char *value)
{
	struct oc_form_opt *opt = calloc(1, sizeof(*opt)), **p;

	if (!opt)
		return NULL;
	opt->type = type;
	opt->name = strdup(name);
	opt->label = strdup(label);
	if (value)
		opt->_value = strdup(value);
	if (!opt->name || !opt->label || (value && !opt->_value)) {
		free(opt->name);
		free(opt->label);
		free(opt->_value);
		free(opt);
		return NULL;
	}

	for (p = &form->opts; *p; p = &(*p)->next)
		;
	*p = opt;
	return opt;
}

static struct oc_auth_form *nx_new_form(const char *auth_id, const char *message)
{
	struct oc_auth_form *form = calloc(1, sizeof(*form));

	if (!form)
		return NULL;
	form->auth_id = strdup(auth_id);
	if (message && *message)
		form->message = strdup(message);
	if (!form->auth_id || (message && *message && !form->message)) {
		free_auth_form(form);
		return NULL;
	}
	return form;
}

/* Ask for a single secret (OTP, challenge response, next tokencode) */
static int nx_prompt_secret(struct openconnect_info *vpninfo, const char *auth_id,
			    const char *name, const char *label,
			    const char *message, char **result)
{
	struct oc_auth_form *form = nx_new_form(auth_id, message);
	struct oc_form_opt *opt;
	int ret;

	*result = NULL;
	if (!form)
		return -ENOMEM;

	opt = nx_add_opt(form, OC_FORM_OPT_PASSWORD, name, label, NULL);
	if (!opt) {
		ret = -ENOMEM;
		goto out;
	}
	if (can_gen_tokencode(vpninfo, form, opt) == 0)
		opt->type = OC_FORM_OPT_TOKEN;

	ret = process_auth_form(vpninfo, form);
	if (ret)
		goto out;

	ret = do_gen_tokencode(vpninfo, form);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
		vpninfo->token_bypassed = 1;
		goto out;
	}

	*result = opt->_value ? strdup(opt->_value) : strdup("");
	if (!*result)
		ret = -ENOMEM;
 out:
	free_auth_form(form);
	return ret;
}

/* Called once the server has issued the 'swap' cookie */
static int nx_finish_login(struct openconnect_info *vpninfo)
{
	const char *swap = nx_cookie_value(vpninfo);
	int days = nx_hdr_int(vpninfo, "X-NE-pwdexpdays", INT_MAX);

	if (days < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Login failed: password has expired and must be changed\n"));
		return -EPERM;
	}
	if (days != INT_MAX)
		vpn_progress(vpninfo, PRG_INFO,
			     _("WARNING: Your password will expire in %d days.\n"), days);

	if (!strcmp(nx_hdr(vpninfo, "X-NE-pda") ?: "", "pdarequired"))
		vpn_progress(vpninfo, PRG_ERR,
			     _("WARNING: Server requests device registration (PDA), which is not supported.\n"));

	free(vpninfo->cookie);
	if (asprintf(&vpninfo->cookie, "%s=%s", NX_COOKIE, swap) < 0) {
		vpninfo->cookie = NULL;
		return -ENOMEM;
	}
	return 0;
}

/* Submit OTP codes to /cgi-bin/otpLogin until accepted or rejected */
static int nx_do_otp(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *body = buf_alloc();
	char *message = NULL, *code = NULL, *resp_buf = NULL;
	int ret, tfresult, attempts = 0;

	if ((ret = buf_error(body)))
		goto out;

	message = strdup(nx_hdr(vpninfo, "X-NE-message") ?: _("Enter one-time password"));
	if (!message) {
		ret = -ENOMEM;
		goto out;
	}

	for (;;) {
		ret = nx_prompt_secret(vpninfo, "_otp", "password",
				       _("One Time Password:"), message, &code);
		if (ret)
			goto out;

		buf_truncate(body);
		append_opt(body, "password", code);
		free_pass(&code);
		if ((ret = buf_error(body)))
			goto out;

		ret = nx_request(vpninfo, "POST", "cgi-bin/otpLogin", body, &resp_buf);
		if (ret < 0)
			goto out;

		tfresult = nx_hdr_int(vpninfo, "X-NE-tfresult", -1);
		free(message);
		message = strdup(nx_hdr(vpninfo, "X-NE-message") ?: "");
		if (!message) {
			ret = -ENOMEM;
			goto out;
		}

		if (tfresult == NX_TFRESULT_OK) {
			vpn_progress(vpninfo, PRG_INFO, _("One-time password accepted\n"));
			ret = 0;
			goto out;
		} else if (tfresult != NX_TFRESULT_RETRY) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("One-time password rejected: %s\n"),
				     *message ? message : _("Authentication failed"));
			ret = -EPERM;
			goto out;
		}
		/* Retry, possibly with a new prompt from the server */
		if (++attempts >= NX_MAX_ATTEMPTS) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Too many failed one-time password attempts\n"));
			ret = -EPERM;
			goto out;
		}
		if (!*message) {
			free(message);
			message = strdup(_("Invalid one-time password; try again."));
		}
	}

 out:
	free_pass(&code);
	free(message);
	free(resp_buf);
	buf_free(body);
	return ret;
}

int netextender_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct oc_auth_form *form = NULL;
	struct oc_form_opt *user_opt, *pass_opt, *domain_opt;
	struct oc_text_buf *body = buf_alloc();
	char *resp_buf = NULL, *secret = NULL, *pstate = NULL, *message = NULL;
	int ret, tf, rounds = 0;

	if ((ret = buf_error(body)))
		goto out;

	/* The 'domain' is a server-side login realm, usually "LocalDomain".
	 * We take it from --authgroup, since there's no way to discover it. */
	form = nx_new_form("_login", NULL);
	if (!form ||
	    !(user_opt = nx_add_opt(form, OC_FORM_OPT_TEXT, "username", _("Username:"), NULL)) ||
	    !(pass_opt = nx_add_opt(form, OC_FORM_OPT_PASSWORD, "password", _("Password:"), NULL)) ||
	    !(domain_opt = nx_add_opt(form, OC_FORM_OPT_HIDDEN, "domain", _("Domain:"),
				      vpninfo->authgroup ?: NX_DEFAULT_DOMAIN))) {
		ret = -ENOMEM;
		goto out;
	}

	ret = process_auth_form(vpninfo, form);
	if (ret)
		goto out;

	buf_truncate(body);
	append_opt(body, "username", user_opt->_value);
	append_opt(body, "password", pass_opt->_value);
	append_opt(body, "domain", domain_opt->_value);
	append_opt(body, "login", "true");

	for (;;) {
		if ((ret = buf_error(body)))
			goto out;

		/* Use HTTP/1.1 connection reuse; login state is all in cookies */
		ret = nx_request(vpninfo, "POST", "cgi-bin/userLogin", body, &resp_buf);
		buf_truncate(body);
		if (ret < 0)
			goto out;

		if (!strcasecmp(nx_hdr(vpninfo, "X-NE-saml") ?: "", "authType:SAML")) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server requires SAML authentication, which is not yet supported for NetExtender\n"));
			ret = -EOPNOTSUPP;
			goto out;
		}
		if (nx_hdr(vpninfo, "X-NE-geobot")) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server requires a CAPTCHA (Geo-IP/Botnet filter): %s\n"),
				     nx_hdr(vpninfo, "X-NE-geobot"));
			ret = -EPERM;
			goto out;
		}

		tf = nx_hdr_int(vpninfo, "X-NE-tf", NX_TF_NONE);
		free(message);
		message = strdup(nx_hdr(vpninfo, "X-NE-message") ?: "");
		free(pstate);
		pstate = strdup(nx_hdr(vpninfo, "X-NE-rsastate") ?: "");
		if (!message || !pstate) {
			ret = -ENOMEM;
			goto out;
		}

		if (nx_cookie_value(vpninfo)) {
			/* First factor accepted */
			if (tf == NX_TF_OTP) {
				ret = nx_do_otp(vpninfo);
				if (ret)
					goto out;
			} else if (tf != NX_TF_NONE) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unknown two-factor authentication scheme %d\n"), tf);
				ret = -EINVAL;
				goto out;
			}
			ret = nx_finish_login(vpninfo);
			goto out;
		}

		/* No cookie yet: either a challenge, or a failure */
		if (tf != NX_TF_NONE && ++rounds > NX_MAX_ATTEMPTS) {
			vpn_progress(vpninfo, PRG_ERR, _("Too many authentication challenges\n"));
			ret = -EPERM;
			goto out;
		}
		switch (tf) {
		case NX_TF_CHALLENGE:
			ret = nx_prompt_secret(vpninfo, "_challenge", "radiusReply",
					       _("Response:"), message, &secret);
			if (ret)
				goto out;
			append_opt(body, "radiusReply", secret);
			append_opt(body, "pstate", pstate);
			append_opt(body, "state", "RADIUSCHALLENGE");
			break;

		case NX_TF_RSA_NEXTTOKEN:
			ret = nx_prompt_secret(vpninfo, "_nexttoken", "nextcode",
					       _("Next tokencode:"),
					       *message ? message : _("Wait for the tokencode to change, then enter the new tokencode."),
					       &secret);
			if (ret)
				goto out;
			append_opt(body, "nextcode", secret);
			append_opt(body, "pstate", pstate);
			append_opt(body, "state", "RSANEWPIN");
			break;

		case NX_TF_RSA_NEWPIN:
		case NX_TF_RSA_SYSPIN:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server requires a new RSA SecurID PIN to be set, which is not supported.\n"
				       "Please set the PIN using the web portal or official client.\n"));
			ret = -EOPNOTSUPP;
			goto out;

		default:
			vpn_progress(vpninfo, PRG_ERR, _("Login failed: %s\n"),
				     *message ? message : _("Authentication failed"));
			ret = -EPERM;
			goto out;
		}
		free_pass(&secret);
		append_opt(body, "username", user_opt->_value);
		append_opt(body, "domain", domain_opt->_value);
	}

 out:
	free_pass(&secret);
	free(pstate);
	free(message);
	free(resp_buf);
	buf_free(body);
	free_auth_form(form);
	free_optlist(vpninfo->nx_resp_hdrs);
	vpninfo->nx_resp_hdrs = NULL;
	return ret;
}

static char *trim(char *s)
{
	char *e;

	while (isspace((unsigned char)*s))
		s++;
	e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = 0;
	return s;
}

static int add_split_include(struct oc_vpn_option **opts, struct oc_ip_info *ip_info,
			     const char *route)
{
	struct oc_split_include *inc = malloc(sizeof(*inc));

	if (!inc)
		return -ENOMEM;
	inc->route = add_option_dup(opts, "split-include", route, -1);
	if (!inc->route) {
		free(inc);
		return -ENOMEM;
	}
	inc->next = ip_info->split_includes;
	ip_info->split_includes = inc;
	return 0;
}

/* Parse the "Key = Value" response from /cgi-bin/sslvpnclient */
static int parse_nx_config(struct openconnect_info *vpninfo, char *buf, int *encap)
{
	struct oc_vpn_option *new_opts = NULL;
	struct oc_ip_info new_ip_info = {};
	struct oc_text_buf *domains = buf_alloc();
	const char *ppp_pref = NULL, *ppp_req = NULL, *ipv6_addr = NULL;
	int tunnel_all = 0, frame_encoded = 0, ipv6_support = 0, n_dns = 0, n_routes = 0;
	char *line, *next, *key, *val, *eq;
	size_t len;
	int ret = 0;

	if (!strstr(buf, "SessionId")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response from NetExtender server; no SessionId found.\n"));
		ret = -EINVAL;
		goto out;
	}

	for (line = buf; line; line = next) {
		next = strchr(line, '\n');
		if (next)
			*next++ = 0;

		eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = 0;
		key = trim(line);
		val = trim(eq + 1);
		/* Real servers wrap these lines in HTML/JavaScript, and some values
		 * have a trailing ';' or are quoted: 'TunnelAllMode = 0;' */
		if (!*key || strpbrk(key, " \t<>\"'()"))
			continue;
		len = strlen(val);
		while (len && (val[len - 1] == ';' || isspace((unsigned char)val[len - 1])))
			val[--len] = 0;
		if (len >= 2 && val[0] == '"' && val[len - 1] == '"') {
			val[len - 1] = 0;
			val++;
		}

		if (!strcmp(key, "SessionId")) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Got NetExtender session\n"));
		} else if (!strcmp(key, "Route")) {
			vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d route %s\n"), 4, val);
			if ((ret = add_split_include(&new_opts, &new_ip_info, val)))
				goto out;
			n_routes++;
		} else if (!strcmp(key, "Ipv6Route")) {
			vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d route %s\n"), 6, val);
			if (!vpninfo->disable_ipv6) {
				if ((ret = add_split_include(&new_opts, &new_ip_info, val)))
					goto out;
				n_routes++;
			}
		} else if (!strcmp(key, "ipv6Support")) {
			ipv6_support = !strcasecmp(val, "yes");
		} else if (!strcmp(key, "GlobalIPv6Addr")) {
			ipv6_addr = add_option_dup(&new_opts, "ipaddr6", val, -1);
		} else if (!strcmp(key, "TunnelAllMode")) {
			tunnel_all = atoi(val);
		} else if (!strcmp(key, "dns1") || !strcmp(key, "dns2")) {
			if (*val && strcmp(val, "0.0.0.0")) {
				vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d DNS server %s\n"), 4, val);
				if (n_dns < 3)
					new_ip_info.dns[n_dns++] = add_option_dup(&new_opts, "DNS", val, -1);
			}
		} else if (!strcmp(key, "dnsSuffix") || !strcmp(key, "dnsSuffixes")) {
			if (*val) {
				vpn_progress(vpninfo, PRG_INFO, _("Got search domain %s\n"), val);
				buf_append(domains, "%s ", val);
			}
		} else if (!strcmp(key, "pppFrameEncoded")) {
			frame_encoded = atoi(val);
		} else if (!strcmp(key, "PppPref")) {
			ppp_pref = add_option_dup(&new_opts, "nx-ppp-pref", val, -1);
		} else if (!strcmp(key, "PppReq")) {
			ppp_req = add_option_dup(&new_opts, "nx-ppp-req", val, -1);
		} else {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Ignoring NetExtender option %s = %s\n"), key, val);
		}
	}

	if (frame_encoded) {
		/* XX: This is a second layer of 0x7e/0x7d byte-stuffing around the
		 * PPP stream, used by old firmware. Not implemented. */
		vpn_progress(vpninfo, PRG_ERR,
			     _("NetExtender server requires the legacy PPP frame encoding (pppFrameEncoded=1), which is not supported. Try updating the server firmware.\n"));
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* PppReq (required) overrides PppPref (preferred). The official client
	 * defaults to async when the server expresses no preference. */
	*encap = PPP_ENCAP_NX_HDLC;
	if (!strcasecmp(ppp_req ?: ppp_pref ?: "", "sync"))
		*encap = PPP_ENCAP_NX;
	vpn_progress(vpninfo, PRG_INFO, _("Using PPP %s mode%s\n"),
		     *encap == PPP_ENCAP_NX ? "sync" : "async",
		     (ppp_req || ppp_pref) ? _(" (chosen by server)") : "");

	if (tunnel_all) {
		vpn_progress(vpninfo, PRG_INFO, _("Server requests that all traffic be tunneled\n"));
		free_split_routes(&new_ip_info);
		new_ip_info.netmask = add_option_dup(&new_opts, "full-netmask", "0.0.0.0", -1);
	} else if (!n_routes) {
		vpn_progress(vpninfo, PRG_ERR, _("NetExtender server sent no routes\n"));
		ret = -EINVAL;
		goto out;
	}

	if (ipv6_support && ipv6_addr && !vpninfo->disable_ipv6) {
		vpn_progress(vpninfo, PRG_INFO, _("Got IPv6 address %s\n"), ipv6_addr);
		if (strchr(ipv6_addr, '/'))
			new_ip_info.netmask6 = ipv6_addr;
		else
			new_ip_info.addr6 = ipv6_addr;
	}

	if (!buf_error(domains) && domains->pos > 0) {
		domains->data[domains->pos - 1] = 0;
		new_ip_info.domain = add_option_steal(&new_opts, "search", &domains->data);
	}

	ret = install_vpn_opts(vpninfo, new_opts, &new_ip_info);
	new_opts = NULL;
	if (ret)
		vpn_progress(vpninfo, PRG_ERR, _("Failed to find VPN options\n"));

 out:
	if (new_opts) {
		free_optlist(new_opts);
		free_split_routes(&new_ip_info);
	}
	buf_free(domains);
	return ret;
}

static int nx_build_connect_req(struct openconnect_info *vpninfo, int encap)
{
	struct oc_text_buf *req = vpninfo->ppp_tls_connect_req;
	const char *swap = nx_cookie_value(vpninfo);
	char *auth = NULL;
	int len, ret;

	if (!swap) {
		vpn_progress(vpninfo, PRG_ERR, _("No cookie named %s.\n"), NX_COOKIE);
		return -EINVAL;
	}

	/* Proxy-Authorization carries the base64-DECODED cookie value */
	auth = openconnect_base64_decode(&len, swap);
	if (!auth || len <= 0 || memchr(auth, 0, len)) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to decode %s cookie\n"), NX_COOKIE);
		free(auth);
		return -EINVAL;
	}

	if (!req)
		req = buf_alloc();
	buf_truncate(req);
	buf_append(req, "CONNECT localhost:0 HTTP/1.0\r\n");
	buf_append(req, "X-SSLVPN-PROTOCOL: 2.0\r\n");
	buf_append(req, "X-SSLVPN-SERVICE: NETEXTENDER\r\n");
	buf_append(req, "Proxy-Authorization:");
	buf_append_bytes(req, auth, len);
	buf_append(req, "\r\n");
	buf_append(req, "X-NX-Client-Platform: Linux\r\n");
	if (encap == PPP_ENCAP_NX_HDLC)
		buf_append(req, "Connection-Medium: MacOS\r\n");
	buf_append(req, "User-Agent: %s\r\n", NX_USER_AGENT);
	buf_append(req, "Frame-Encode: off\r\n");
	buf_append(req, "X-NE-PROTOCOL: 2.0\r\n");
	buf_append(req, "\r\n");

	clear_mem(auth, len);
	free(auth);

	vpninfo->ppp_tls_connect_req = req;
	if ((ret = buf_error(req)))
		vpn_progress(vpninfo, PRG_ERR, _("Error building NetExtender tunnel request\n"));
	return ret;
}

static int netextender_configure(struct openconnect_info *vpninfo)
{
	char *resp_buf = NULL, *swap = NULL;
	char path[80];
	int ret, encap;

	if (!vpninfo->cookies) {
		/* This will happen if authentication was separate/external */
		ret = internal_split_cookies(vpninfo, 1, NX_COOKIE);
		if (ret)
			return ret;
	}
	if (!nx_cookie_value(vpninfo)) {
		vpn_progress(vpninfo, PRG_ERR, _("No cookie named %s.\n"), NX_COOKIE);
		return -EINVAL;
	}
	swap = strdup(nx_cookie_value(vpninfo));
	if (!swap)
		return -ENOMEM;

	snprintf(path, sizeof(path),
		 "cgi-bin/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=%s",
		 vpninfo->disable_ipv6 ? "no" : "yes");
	ret = nx_request(vpninfo, "GET", path, NULL, &resp_buf);

	/* XX: The server answers this with a *second* 'swap' cookie holding the
	 * base64-decoded session ID. The official client ignores it and keeps
	 * using the original (base64) cookie, both here and for logout. If we
	 * kept the new one, we'd decode it again for Proxy-Authorization. */
	http_add_cookie(vpninfo, NX_COOKIE, swap, 1);
	if (ret < 0)
		goto out;

	if (nx_hdr_int(vpninfo, "X-NE-error", 0)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("NetExtender server refused connection: %s\n"),
			     nx_hdr(vpninfo, "X-NE-message") ?: _("unknown error"));
		ret = -EPERM;
		goto out;
	}
	if (!resp_buf || !ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Empty response to NetExtender configuration request\n"));
		ret = -EINVAL;
		goto out;
	}

	ret = parse_nx_config(vpninfo, resp_buf, &encap);
	if (ret)
		goto out;

	ret = nx_build_connect_req(vpninfo, encap);
	if (ret)
		goto out;

	ret = openconnect_ppp_new(vpninfo, encap, 1,
				  !!(vpninfo->ip_info.addr6 || vpninfo->ip_info.netmask6));
 out:
	free_optlist(vpninfo->nx_resp_hdrs);
	vpninfo->nx_resp_hdrs = NULL;
	free_pass(&swap);
	free(resp_buf);
	return ret;
}

int netextender_connect(struct openconnect_info *vpninfo)
{
	int ret;

	if (!vpninfo->ppp) {
		/* XX: Fetch the configuration only once. The server assigns
		 * the IP address via IPCP, and re-fetching the configuration
		 * on reconnect would make install_vpn_opts() complain. */
		ret = netextender_configure(vpninfo);
	} else {
		ret = ppp_reset(vpninfo);
	}
	if (ret) {
	err:
		openconnect_close_https(vpninfo, 0);
		return ret;
	}

	ret = ppp_tcp_should_connect(vpninfo);
	if (ret <= 0) {
		if (!ret)
			ret = -EIO;
		goto err;
	}

	/* The tunnel needs a connection of its own */
	openconnect_close_https(vpninfo, 0);
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto err;

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', vpninfo->ppp_tls_connect_req->data);
	ret = vpninfo->ssl_write(vpninfo, vpninfo->ppp_tls_connect_req->data,
				 vpninfo->ppp_tls_connect_req->pos);
	if (ret < 0)
		goto err;

	/* No HTTP response on success; PPP frames just start flowing. On
	 * failure (e.g. 407 for an invalid session) we get an HTTP response,
	 * which the PPP mainloop will catch. */
	vpninfo->ppp->check_http_response = 1;

	monitor_fd_new(vpninfo, ssl);
	monitor_read_fd(vpninfo, ssl);
	monitor_except_fd(vpninfo, ssl);

	/* Trigger the first PPP negotiations and ensure the PPP state
	 * is PPPS_ESTABLISH so that ppp_tcp_mainloop() knows we've started. */
	ppp_start_tcp_mainloop(vpninfo);

	return 0;
}

int netextender_bye(struct openconnect_info *vpninfo, const char *reason)
{
	struct oc_text_buf *body = buf_alloc();
	char *orig_path, *resp_buf = NULL;
	int ret;

	/* Close the tunnel connection, then log out on a new one */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = NULL;
	ret = nx_request(vpninfo, "POST", "cgi-bin/userLogout", body, &resp_buf);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	if (ret < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));

	free_optlist(vpninfo->nx_resp_hdrs);
	vpninfo->nx_resp_hdrs = NULL;
	free(resp_buf);
	buf_free(body);
	return ret;
}
