/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
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

#include <config.h>

#include "openconnect-internal.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

int xmlnode_is_named(xmlNode *xml_node, const char *name)
{
	return !strcmp((char *)xml_node->name, name);
}

/* similar to auth.c's xmlnode_get_text, including that *var should be freed by the caller,
   but without the hackish param / %s handling that Cisco needs. */
int xmlnode_get_val(xmlNode *xml_node, const char *name, char **var)
{
	char *str;

	if (name && !xmlnode_is_named(xml_node, name))
		return -EINVAL;

	str = (char *)xmlNodeGetContent(xml_node);
	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

int xmlnode_get_prop(xmlNode *xml_node, const char *name, char **var)
{
	char *str = (char *)xmlGetProp(xml_node, (unsigned char *)name);

	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

int xmlnode_match_prop(xmlNode *xml_node, const char *name, const char *match)
{
	char *str = (char *)xmlGetProp(xml_node, (unsigned char *)name);
	int ret = 0;

	if (!str)
		return -ENOENT;

	if (strcmp(str, match))
		ret = -EEXIST;

	free(str);
	return ret;
}

int xmlnode_get_trimmed_val(xmlNode *xml_node, const char *name, char **var)
{

	char *p, *str;
	int i, len;

	if (name && !xmlnode_is_named(xml_node, name))
		return -EINVAL;

	str = (char *)xmlNodeGetContent(xml_node);
	if (!str)
		return -ENOENT;

	/* Trim trailing space */
	len = strlen(str);
	for (i = len-1; i >= 0; i--) {
		if (isspace((int)(unsigned char)str[i]))
			str[i] = 0;
		else
			break;
	}

	/* Trim leading space */
	for (p = str; isspace((int)(unsigned char)*p); p++)
		;

	/* Treat empty string as missing */
	if (!*p) {
		free(str);
		return -ENOENT;
	}

	if (p == str)
		*var = str;
	else {
		*var = strdup(p);
		free(str);
	}
	return 0;
}

int xmlnode_bool_or_int_value(xmlNode *node)
{
	int ret = -1;
	char *content = (char *)xmlNodeGetContent(node);
	if (!content)
		return -1;

	if (isdigit(content[0]))
		ret = atoi(content);
	else if (!strcasecmp(content, "yes") || !strcasecmp(content, "on"))
		ret = 1;
	else if (!strcasecmp(content, "no") || !strcasecmp(content, "off"))
		ret = 0;

	free(content);
	return ret;
}

int append_opt(struct oc_text_buf *body, const char *opt, const char *name)
{
	if (buf_error(body))
		return buf_error(body);

	if (body->pos)
		buf_append(body, "&");

	buf_append_urlencoded(body, opt);
	buf_append(body, "=");
	buf_append_urlencoded(body, name);

	return 0;
}

int append_form_opts(struct openconnect_info *vpninfo,
			    struct oc_auth_form *form, struct oc_text_buf *body)
{
	struct oc_form_opt *opt;
	int ret;

	for (opt = form->opts; opt; opt = opt->next) {
		ret = append_opt(body, opt->name, opt->_value);
		if (ret)
			return ret;
	}
	return 0;
}

void clear_mem(void *p, size_t s)
{
#if defined(HAVE_MEMSET_S)
	memset_s(p, s, 0x5a, s);
#elif defined(HAVE_EXPLICIT_MEMSET)
	explicit_memset(p, 0x5a, s);
#elif defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(p, s);
#elif defined(_WIN32)
	SecureZeroMemory(p, s);
#else
	volatile char *pp = (volatile char *)p;
	while (s--)
		*(pp++) = 0x5a;
#endif
}

void free_pass(char **p)
{
	if (!*p)
		return;

	clear_mem(*p, strlen(*p));
	free(*p);
	*p = NULL;
}

void free_opt(struct oc_form_opt *opt)
{
	if (!opt)
		return;

	/* for SELECT options, opt->value is a pointer to oc_choice->name */
	if (opt->type != OC_FORM_OPT_SELECT) {
		free_pass(&opt->_value);
	} else {
		struct oc_form_opt_select *sel = (void *)opt;
		int i;

		for (i = 0; i < sel->nr_choices; i++) {
			free(sel->choices[i]->name);
			free(sel->choices[i]->label);
			free(sel->choices[i]->auth_type);
			free(sel->choices[i]->override_name);
			free(sel->choices[i]->override_label);
			free(sel->choices[i]);
		}
		free(sel->choices);
	}

	free(opt->name);
	free(opt->label);
	free(opt);
}

void free_auth_form(struct oc_auth_form *form)
{
	if (!form)
		return;
	while (form->opts) {
		struct oc_form_opt *tmp = form->opts->next;
		free_opt(form->opts);
		form->opts = tmp;
	}
	free(form->error);
	free(form->message);
	free(form->banner);
	free(form->auth_id);
	free(form->method);
	free(form->action);
	free(form);
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
int do_gen_tokencode(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form)
{
	struct oc_form_opt *opt;

	for (opt = form->opts; ; opt = opt->next) {
		/* this form might not have anything for us to do */
		if (!opt)
			return 0;
		if (opt->type == OC_FORM_OPT_TOKEN)
			break;
	}

	switch (vpninfo->token_mode) {
#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return do_gen_stoken_code(vpninfo, form, opt);
#endif
	case OC_TOKEN_MODE_TOTP:
		return do_gen_totp_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_HOTP:
		return do_gen_hotp_code(vpninfo, form, opt);
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return do_gen_yubikey_code(vpninfo, form, opt);
#endif
	default:
		return -EINVAL;
	}
}

int can_gen_tokencode(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt)
{
	switch (vpninfo->token_mode) {
#ifdef HAVE_LIBSTOKEN
	case OC_TOKEN_MODE_STOKEN:
		return can_gen_stoken_code(vpninfo, form, opt);
#endif
	case OC_TOKEN_MODE_TOTP:
		return can_gen_totp_code(vpninfo, form, opt);

	case OC_TOKEN_MODE_HOTP:
		return can_gen_hotp_code(vpninfo, form, opt);
#ifdef HAVE_LIBPCSCLITE
	case OC_TOKEN_MODE_YUBIOATH:
		return can_gen_yubikey_code(vpninfo, form, opt);
#endif
	default:
		return -EINVAL;
	}
}

/****************************************************************************/

/* Harvest the cookies handed back by a webview session. Any cookie whose
 * name appears in vpninfo->sso_cookie_names is copied into the HTTP cookie
 * jar. Once the primary session cookie (the first list entry) has been
 * seen, return 0 so that the webview is closed; otherwise ask the webview
 * to keep going. */
int oc_sso_detect_done(struct openconnect_info *vpninfo,
		       const struct oc_webview_result *result)
{
	int i, j;

	if (!vpninfo->sso_cookie_names)
		return -EINVAL;

	for (i = 0; result->cookies != NULL && result->cookies[i] != NULL; i += 2) {
		const char *cname = result->cookies[i], *cval = result->cookies[i+1];

		if (!cval || !cval[0])
			continue;

		for (j = 0; vpninfo->sso_cookie_names[j]; j++) {
			if (strcmp(cname, vpninfo->sso_cookie_names[j]))
				continue;
			http_add_cookie(vpninfo, cname, cval, 1);
			break;
		}
		if (j == 0)
			return 0; /* Primary session cookie: webview done */
	}

	/* Keep the webview going; the cookies may appear at any time */
	return -EAGAIN;
}

/* Complete an SSO authentication by opening the given URI in the host's
 * webview (as registered with openconnect_set_webview_callback()) and
 * waiting for the user to complete the login. After the webview is done,
 * the original gateway URL is restored - the redirect chain may have
 * switched to the IdP's host in the meantime, and that host must not be
 * mistaken for the tunnel gateway. */
int oc_webauth_run(struct openconnect_info *vpninfo, const char *uri)
{
	char *saved_url = internal_get_url(vpninfo);
	char *proto = NULL, *host = NULL, *path = NULL;
	int port = 0, ret;

	if (!vpninfo->open_webview)
		return -EINVAL;

	vpn_progress(vpninfo, PRG_INFO,
		     _("Launching web browser for SSO authentication at %s\n"), uri);

	ret = vpninfo->open_webview(vpninfo, uri, vpninfo->cbdata);
	if (ret >= 0 && saved_url &&
	    !internal_parse_url(saved_url, &proto, &host, &port, &path, -1)) {
		if (host && strcmp(host, vpninfo->hostname)) {
			free(vpninfo->hostname);
			vpninfo->hostname = strdup(host);
			vpninfo->port = port;
			free(vpninfo->urlpath);
			vpninfo->urlpath = path ? path : NULL;
			path = NULL;
			vpn_progress(vpninfo, PRG_INFO,
				     _("Restoring original gateway URL %s after web authentication\n"),
				     saved_url);
		} else if (path) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = path;
			path = NULL;
		}
	}
	free(proto);
	free(host);
	free(path);
	free(saved_url);

	return ret;
}
