/* Experimental Huawei UniVPN IPv4 over two TLS channels.
 * Copyright (C) 2026 UniVPN Connect contributors. LGPL-2.1-or-later.
 * Wire observations are documented in www/huawei.xml. */
#include <config.h>
#include "openconnect-internal.h"
#include "univpn-codec.h"

struct uv_channel {
	unsigned char rx[UV_HEADER + UV_MAX_PAYLOAD];
	unsigned char tx[UV_HEADER + UV_MAX_PAYLOAD];
	unsigned rxused, rxwant, txused, txsent;
};
struct univpn_state {
	struct openconnect_info *owner, *data;
	struct uv_channel control, packets;
	unsigned char token[32];
	char *peer_hash;
	time_t started, control_due, data_due;
};

void univpn_shutdown(struct openconnect_info *v)
{
	struct univpn_state *s = v->univpn;
	if (!s) return;
	v->univpn = NULL;
	if (v->aux_ssl_fd >= 0) {
		unmonitor_fd(v, aux_ssl);
		v->aux_ssl_fd = -1;
	}
	if (s->data) openconnect_vpninfo_free(s->data);
	free(s->peer_hash);
	clear_mem(s, sizeof(*s));
	free(s);
}
int univpn_bye(struct openconnect_info *v, const char *reason)
{
	univpn_shutdown(v);
	openconnect_close_https(v, 0);
	return 0;
}

static int uv_wait(struct openconnect_info *owner, int fd, int writing, time_t deadline)
{
	fd_set r, w; struct timeval tv = { 0, 100000 }; int maxfd = fd, ret;
	FD_ZERO(&r); FD_ZERO(&w);
	if (writing) FD_SET(fd, &w); else FD_SET(fd, &r);
	cmd_fd_set(owner, &r, &maxfd);
	ret = select(maxfd + 1, &r, &w, NULL, &tv);
	if (ret < 0 && errno != EINTR) return -errno;
	if (is_cancel_pending(owner, &r)) return -EINTR;
	return time(NULL) >= deadline ? -ETIMEDOUT : 0;
}
static int uv_frame(struct uv_channel *c, unsigned cmd, const void *p, unsigned len)
{
	if (c->txused || len > UV_MAX_PAYLOAD) return -EINVAL;
	memcpy(c->tx, "\xc1\x92\xa4\xd6\x01", 5);
	c->tx[5] = cmd; store_be16(c->tx + 6, len);
	if (len) memcpy(c->tx + 8, p, len);
	c->txused = len + 8; c->txsent = 0;
	return 0;
}
/* Keep the exact TLS retry buffer until the backend consumes it. */
static int uv_write(struct openconnect_info *tls, struct uv_channel *c)
{
	int n;
	if (!c->txused) return 0;
	n = ssl_nonblock_write(tls, 0, c->tx + c->txsent, c->txused - c->txsent);
	if (n < 0) return -EIO;
	if (!n) return 0;
	c->txsent += n;
	if (c->txsent == c->txused) {
		clear_mem(c->tx, c->txused);
		c->txused = c->txsent = 0;
		unmonitor_write_fd(tls, ssl);
	}
	return 1;
}
/* 1 = complete frame; 0 = would block/partial; negative = invalid/closed. */
static int uv_read(struct openconnect_info *tls, struct uv_channel *c)
{
	unsigned cmd, len; int n;
	if (!c->rxwant) c->rxwant = UV_HEADER;
	for (;;) {
		n = ssl_nonblock_read(tls, 0, c->rx + c->rxused, c->rxwant - c->rxused);
		if (n < 0) return -EIO;
		if (!n) return 0;
		c->rxused += n;
		if (c->rxused != c->rxwant) continue;
		if (c->rxwant == UV_HEADER) {
			if (uv_header(c->rx, c->rxused, &cmd, &len) != 1) return -EINVAL;
			c->rxwant += len;
		}
		if (c->rxused == c->rxwant) return 1;
	}
}
static void uv_consumed(struct uv_channel *c)
{
	clear_mem(c->rx, c->rxused);
	c->rxused = 0; c->rxwant = UV_HEADER;
}
static int uv_exchange(struct openconnect_info *owner, struct openconnect_info *tls,
		       struct uv_channel *c, unsigned expected)
{
	time_t deadline = time(NULL) + 30; int ret;
	while (c->txused) {
		ret = uv_write(tls, c);
		if (ret < 0) return ret;
		if (!ret && (ret = uv_wait(owner, tls->ssl_fd, 1, deadline))) return ret;
	}
	while (!(ret = uv_read(tls, c))) {
		ret = uv_wait(owner, tls->ssl_fd, 0, deadline);
		if (ret) return ret;
	}
	if (ret < 0) return ret;
	return c->rx[5] == expected ? 0 : -EINVAL;
}
static void uv_escape(struct oc_text_buf *b, const char *value)
{
	for (; *value; value++) {
		if (*value == '%' || *value == '&' || *value == '+')
			buf_append(b, "%%%02X", (unsigned char)*value);
		else buf_append_bytes(b, value, 1);
	}
	buf_append_zeroes(b, 1);
}
static int uv_auth_field(struct oc_text_buf *b, unsigned type, const char *value, int escaped)
{
	struct oc_text_buf *tmp = buf_alloc(); int ret;
	if (!tmp) return -ENOMEM;
	if (escaped) uv_escape(tmp, value); else buf_append_bytes(tmp, value, strlen(value));
	ret = buf_error(tmp);
	if (!ret && tmp->pos <= 65535) {
		buf_append_be16(b, type); buf_append_be16(b, tmp->pos);
		buf_append_bytes(b, tmp->data, tmp->pos);
	} else if (!ret) ret = -E2BIG;
	clear_mem(tmp->data, tmp->pos); buf_free(tmp);
	return ret;
}
static int uv_vip(struct openconnect_info *v, const unsigned char *p, unsigned n)
{
	struct oc_ip_info info = { 0 }; struct oc_vpn_option *opts = NULL;
	unsigned type, len; const unsigned char *value; size_t pos = 4; int ret;
	char text[64], mask[16]; unsigned char netmask[4];
	if (n < 4 || p[0]) { ret = -EPERM; goto out; }
	while ((ret = uv_tlv(p, n, &pos, &type, &value, &len)) > 0) {
		if (type == 1) {
			uint32_t bits;
			if (len != 5 || value[4] > 32 || info.addr) { ret = -EINVAL; goto out; }
			inet_ntop(AF_INET, value, text, sizeof(text));
			info.addr = add_option_dup(&opts, "ipaddr", text, -1);
			bits = value[4] ? UINT32_MAX << (32 - value[4]) : 0;
			store_be32(netmask, bits); inet_ntop(AF_INET, netmask, mask, sizeof(mask));
			info.netmask = add_option_dup(&opts, "netmask", mask, -1);
			if (!info.addr || !info.netmask) { ret = -ENOMEM; goto out; }
		} else if (type == 6) {
			if (len % 5) { ret = -EINVAL; goto out; }
			for (unsigned i = 0; i < len; i += 5) {
				struct oc_split_include *inc;
				if (!uv_route(value + i)) { ret = -EINVAL; goto out; }
				inet_ntop(AF_INET, value + i, text, sizeof(text));
				snprintf(text + strlen(text), sizeof(text) - strlen(text), "/%u", value[i+4]);
				inc = calloc(1, sizeof(*inc)); if (!inc) { ret = -ENOMEM; goto out; }
				inc->route = add_option_dup(&opts, "split-include", text, -1);
				if (!inc->route) { free(inc); { ret = -ENOMEM; goto out; } }
				inc->next = info.split_includes; info.split_includes = inc;
			}
		}
	}
	if (ret < 0 || !info.addr) { ret = -EINVAL; goto out; }
	info.mtu = v->reqmtu ? v->reqmtu : 1400;
	if (info.mtu < 576 || info.mtu > 65527) { ret = -EINVAL; goto out; }
	ret = install_vpn_opts(v, opts, &info);
	if (!ret) return 0;
out:
	free_split_routes(&info); free_optlist(opts);
	return ret;
}
int univpn_obtain_cookie(struct openconnect_info *v)
{
	struct univpn_state *s; struct oc_auth_form *form = NULL;
	struct oc_form_opt *user, *pass; struct oc_text_buf *b = NULL;
	const char *domain = v->authgroup ? v->authgroup : v->hostname;
	unsigned char first[340] = {0}, hash[32];
	unsigned type, len; const unsigned char *value; size_t pos; int ret, found = 0;
	char mac[18];
	if (!domain || strlen(domain) > 255 || v->proxy) { vpn_progress(v, PRG_ERR, "UniVPN invalid domain or unsupported proxy configuration\n"); return -EINVAL; }
	univpn_shutdown(v);
	s = calloc(1, sizeof(*s)); if (!s) return -ENOMEM;
	v->univpn = s; s->owner = v;
	form = calloc(1, sizeof(*form)); user = calloc(1, sizeof(*user)); pass = calloc(1, sizeof(*pass));
	if (!form || !user || !pass) { free(form); form = NULL; free(user); free(pass); ret = -ENOMEM; goto out; }
	form->auth_id = strdup("univpn"); form->opts = user; user->next = pass;
	user->type = OC_FORM_OPT_TEXT; user->name = strdup("username"); user->label = strdup("Username:");
	pass->type = OC_FORM_OPT_PASSWORD; pass->name = strdup("password"); pass->label = strdup("Password:");
	if (!form->auth_id || !user->name || !user->label || !pass->name || !pass->label) { ret = -ENOMEM; goto out; }
	ret = process_auth_form(v, form);
	if (ret || !user->_value || !pass->_value) { ret = -EINTR; goto out; }
	ret = openconnect_open_https(v); if (ret) goto out;
	ret = set_sock_nonblock(v->ssl_fd); if (ret) goto out;
	memcpy(first, "\xfe\xfc\xef\xbe\xc1\x92\xa4\xd6", 8);
	store_be16(first + 12, 29); store_be16(first + 14, 324);
	memcpy(first + 80, domain, strlen(domain)); first[337] = 1;
	memcpy(s->control.tx, first, sizeof(first)); s->control.txused = sizeof(first);
	ret = uv_exchange(v, v, &s->control, 0); if (ret) goto out;
	if (s->control.rxused != 12 || load_be32(s->control.rx + 8)) { ret = -EINVAL; goto out; }
	uv_consumed(&s->control);
	b = buf_alloc(); if (!b) { ret = -ENOMEM; goto out; }
	buf_append_bytes(b, domain, strlen(domain)); buf_append_zeroes(b, 260 - strlen(domain));
	ret = openconnect_sha256(hash, user->_value, strlen(user->_value)); if (ret) goto out;
	snprintf(mac, sizeof(mac), "02:%02x:%02x:%02x:%02x:%02x", hash[1], hash[2], hash[3], hash[4], hash[5]);
	if ((ret = uv_auth_field(b, 1, user->_value, 1)) || (ret = uv_auth_field(b, 2, pass->_value, 1)) ||
	    (ret = uv_auth_field(b, 3, mac, 0)) || (ret = buf_error(b))) goto out;
	ret = uv_frame(&s->control, 1, b->data, b->pos); if (ret) goto out;
	clear_mem(b->data, b->pos); buf_free(b); b = NULL;
	free_auth_form(form); form = NULL;
	ret = uv_exchange(v, v, &s->control, 1); if (ret) goto out;
	if (s->control.rxused < 16) { ret = -EINVAL; goto out; }
	if (load_be32(s->control.rx + 8)) { ret = -EPERM; goto out; }
	pos = 8;
	while ((ret = uv_tlv(s->control.rx + 8, s->control.rxused - 8, &pos, &type, &value, &len)) > 0) {
		if (type == 3) { if (len != 32 || found) { ret = -EINVAL; goto out; } memcpy(s->token, value, 32); found = 1; }
	}
	if (ret < 0 || !found) { ret = -EINVAL; goto out; }
	uv_consumed(&s->control);
	ret = uv_frame(&s->control, 3, s->token, 32); if (ret) goto out;
	ret = uv_exchange(v, v, &s->control, 3); if (ret) goto out;
	ret = uv_vip(v, s->control.rx + 8, s->control.rxused - 8); if (ret) goto out;
	uv_consumed(&s->control);
	if (!openconnect_get_peer_cert_hash(v)) { ret = -EPERM; goto out; }
	s->peer_hash = strdup(openconnect_get_peer_cert_hash(v));
	if (!s->peer_hash) { ret = -ENOMEM; goto out; }
	/* This token is meaningful only while its authenticated control channel is open. */
	b = buf_alloc(); if (!b) { ret = -ENOMEM; goto out; }
	for (int i = 0; i < 32; i++) buf_append(b, "%02x", s->token[i]);
	ret = buf_error(b); if (ret) goto out;
	free_pass(&v->cookie); v->cookie = strdup(b->data);
	if (!v->cookie) { ret = -ENOMEM; goto out; }
	vpn_progress(v, PRG_INFO, _("UniVPN authentication and IPv4 configuration received\n"));
	ret = 0;
out:
	if (b) { clear_mem(b->data, b->pos); buf_free(b); }
	if (form) free_auth_form(form);
	if (ret) { vpn_progress(v, PRG_ERR, "UniVPN authentication failed (%d)\n", ret); univpn_shutdown(v); openconnect_close_https(v, 0); }
	return ret;
}
static int uv_validate_data(void *priv, const char *reason)
{
	struct univpn_state *s = priv;
	return openconnect_check_peer_cert_hash(s->data, s->peer_hash) ? -EPERM : 0;
}
static void __attribute__((format(printf, 3, 4))) uv_progress(void *priv, int level, const char *fmt, ...)
{
	struct univpn_state *s = priv; va_list ap; char line[1024];
	va_start(ap, fmt); vsnprintf(line, sizeof(line), fmt, ap); va_end(ap);
	vpn_progress(s->owner, level, "%s", line);
}
int univpn_connect(struct openconnect_info *v)
{
	struct univpn_state *s = v->univpn; int ret;
	if (!s || v->ssl_fd < 0) {
		vpn_progress(v, PRG_ERR, _("UniVPN requires a live authenticated control channel; cookie-only reconnect is unsupported\n"));
		return -EPERM;
	}
	if (s->data) return -EINVAL;
	s->data = openconnect_vpninfo_new(v->useragent, uv_validate_data, NULL, NULL, uv_progress, s);
	if (!s->data) return -ENOMEM;
#define COPY(field) do { if (v->field && !(s->data->field = strdup(v->field))) return -ENOMEM; } while (0)
	COPY(hostname); COPY(unique_hostname); COPY(sni); COPY(cafile); COPY(ciphersuite_config);
#undef COPY
	s->data->port = v->port; s->data->no_system_trust = v->no_system_trust;
	s->data->no_tls13 = v->no_tls13; s->data->pfs = v->pfs;
	s->data->allow_insecure_crypto = v->allow_insecure_crypto;
	/* Share cancellation only during the child handshake; ownership stays with the parent. */
	s->data->cmd_fd = v->cmd_fd;
	s->data->cmd_fd_internal = v->cmd_fd_internal;
	ret = openconnect_open_https(s->data);
	v->got_cancel_cmd |= s->data->got_cancel_cmd;
	v->got_pause_cmd |= s->data->got_pause_cmd;
	s->data->cmd_fd = -1;
	if (ret) return ret;
	ret = set_sock_nonblock(s->data->ssl_fd); if (ret) return ret;
	ret = openconnect_check_peer_cert_hash(s->data, s->peer_hash); if (ret) return -EPERM;
	ret = uv_frame(&s->packets, 0x64, s->token, 32); if (ret) return ret;
	ret = uv_exchange(v, s->data, &s->packets, 0x64); if (ret) return ret;
	if (s->packets.rxused != 9 || s->packets.rx[8]) return -EPERM;
	uv_consumed(&s->packets);
	v->aux_ssl_fd = s->data->ssl_fd;
	monitor_fd_new(v, aux_ssl); monitor_read_fd(v, aux_ssl); monitor_except_fd(v, aux_ssl);
	monitor_read_fd(v, ssl); monitor_except_fd(v, ssl);
	s->started = time(NULL); s->control_due = s->started + 10; s->data_due = s->started + 15;
	vpn_progress(v, PRG_INFO, _("UniVPN IPv4/TLS data channel connected\n"));
	return 0;
}
int univpn_mainloop(struct openconnect_info *v, int *timeout, int readable)
{
	struct univpn_state *s = v->univpn; time_t now = time(NULL); int ret, work = 0;
	if (!s || !s->data || v->ssl_fd < 0) goto failed;
	/* Both sessions may have decrypted bytes even without a new socket event. */
	for (int channel = 0; channel < 2; channel++) {
		struct uv_channel *c = channel ? &s->packets : &s->control;
		struct openconnect_info *tls = channel ? s->data : v;
		for (int frames = 0; frames < 32; frames++) {
			ret = uv_read(tls, c); if (ret < 0) goto failed;
			if (!ret) break;
			if (channel) {
				if (c->rx[5] == 0x66) {
					if (c->rxused < 36 || memcmp(c->rx + 8, "\0\0\0\0\0\0\0\0", 8) ||
					    !uv_ipv4(c->rx + 16, c->rxused - 16)) goto failed;
					ret = queue_new_packet(v, &v->incoming_queue, c->rx + 16, c->rxused - 16);
					if (ret < 0) goto failed;
				} else if (c->rx[5] != 0x65) goto failed;
			} else if (c->rx[5] != 6) goto failed;
			uv_consumed(c); work = 1;
		}
	}
	if (!s->control.txused && ka_check_deadline(timeout, now, s->control_due)) {
		unsigned char beat[36]; memcpy(beat, s->token, 32);
		store_be32(beat + 32, (uint32_t)(now - s->started) * 1000);
		uv_frame(&s->control, 6, beat, sizeof(beat)); clear_mem(beat, sizeof(beat)); s->control_due = now + 10;
	}
	if (!s->packets.txused && ka_check_deadline(timeout, now, s->data_due)) {
		uv_frame(&s->packets, 0x65, NULL, 0); s->data_due = now + 15;
	}
	if (!s->packets.txused && v->outgoing_queue.count) {
		struct pkt *pkt = dequeue_packet(&v->outgoing_queue);
		if (pkt->len > 65527 || !uv_ipv4(pkt->data, pkt->len)) { free_pkt(v, pkt); goto failed; }
		memcpy(s->packets.tx, "\xc1\x92\xa4\xd6\x01\x66", 6);
		store_be16(s->packets.tx + 6, pkt->len + 8); memset(s->packets.tx + 8, 0, 8);
		memcpy(s->packets.tx + 16, pkt->data, pkt->len); s->packets.txused = pkt->len + 16;
		free_pkt(v, pkt);
	}
	ret = uv_write(v, &s->control); if (ret < 0) goto failed; work |= ret;
	ret = uv_write(s->data, &s->packets); if (ret < 0) goto failed; work |= ret;
	if (s->packets.txused) monitor_write_fd(v, aux_ssl); else unmonitor_write_fd(v, aux_ssl);
	return work;
failed:
	v->quit_reason = "UniVPN channel closed or invalid frame; fresh authentication required";
	vpn_progress(v, PRG_ERR, "%s\n", v->quit_reason);
	return -EIO;
}
