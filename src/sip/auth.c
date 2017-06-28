/**
 * @file sip/auth.c  SIP Authentication
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <string.h>
#include <re_types.h>
#include <re_mem.h>
#include <re_fmt.h>
#include <re_mbuf.h>
#include <re_uri.h>
#include <re_list.h>
#include <re_sa.h>
#include <re_sys.h>
#include <re_md5.h>
#include <re_httpauth.h>
#include <re_udp.h>
#include <re_msg.h>
#include <re_sip.h>
#include "sip.h"


struct sip_auth {
	struct list realml;
	sip_auth_h *authh;
	void *arg;
	bool ref;
	int err;
};


struct realm {
	struct le le;
	char *realm;
	char *nonce;
	char *qop;
	char *opaque;
	char *user;
	char *pass;
	int pass_len;
	uint32_t nc;
	enum sip_hdrid hdr;
};


static int dummy_handler(char **user, char **pass, int *pass_len, 
			const char *rlm, char *algorithm, char *nonce, void *arg)
{
	(void)user;
	(void)pass;
	(void)pass_len;
	(void)rlm;
	(void)arg;
	(void)algorithm;
	(void)nonce;

	return EAUTH;
}


static void realm_destructor(void *arg)
{
	struct realm *realm = arg;

	list_unlink(&realm->le);
	mem_deref(realm->realm);
	mem_deref(realm->nonce);
	mem_deref(realm->qop);
	mem_deref(realm->opaque);
	mem_deref(realm->user);
	mem_deref(realm->pass);
}


static void auth_destructor(void *arg)
{
	struct sip_auth *auth = arg;

	if (auth->ref)
		mem_deref(auth->arg);

	list_flush(&auth->realml);
}


static int mkdigest(uint8_t *digest, const struct realm *realm,
		    const char *met, const char *uri, uint64_t cnonce)
{
	uint8_t ha1[MD5_SIZE], ha2[MD5_SIZE];
	int err;

	/* Here the algorithm directive's value is "MD5" or unspecified,
	so HA1 is HA1 = MD5(username:realm:password) */

	char temp_str[100];
	sprintf(temp_str, "%.*s", realm->pass_len, realm->pass);
	err = md5_printf(ha1, "%s:%s:%s",
			 realm->user, realm->realm, temp_str);

	if (err)
		return err;

    /* The qop directive's value is "auth" or is unspecified,
    so HA2 is HA2 = MD5(method:digestURI) */
	err = md5_printf(ha2, "%s:%s", met, uri);
	if (err)
		return err;

    /* If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
    response (here digest) = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2) */
	if (realm->qop)
		return md5_printf(digest, "%w:%s:%08x:%016llx:auth:%w",
				  ha1, sizeof(ha1),
				  realm->nonce,
				  realm->nc,
				  cnonce,
				  ha2, sizeof(ha2));

	/*If the qop directive is unspecified, then compute the response as follows:
	response (here digest) = MD5(HA1:nonce:HA2) */
	else
		return md5_printf(digest, "%w:%s:%w",
				  ha1, sizeof(ha1),
				  realm->nonce,
				  ha2, sizeof(ha2));
}


static bool cmp_handler(struct le *le, void *arg)
{
	struct realm *realm = le->data;
	struct pl *chrealm = arg;

	/* handle multiple authenticate headers with equal realm value */
	if (realm->nc == 1)
		return false;

	return 0 == pl_strcasecmp(chrealm, realm->realm);
}


static bool auth_handler(const struct sip_hdr *hdr, const struct sip_msg *msg,
			 void *arg)
{
	struct httpauth_digest_chall ch;
	struct sip_auth *auth = arg;
	struct realm *realm = NULL;
	int err;
	(void)msg;

    /* Decode the authentication challenge from the registrar */
	if (httpauth_digest_challenge_decode(&ch, &hdr->val)) {
		err = EBADMSG;
		goto out;
	}

	/* Verify the authentication mechanism used */
	/* strncmp(a, b, m) compares the first m characters in a and b */
    if (!pl_isset(&ch.algorithm) || 
    	(strncmp((ch.algorithm).p, "MD5", 3) && 
    	strncmp((ch.algorithm).p, "AKAv1", 5) &&
        strncmp((ch.algorithm).p, "AKAv2", 5)))
    {
    	err = ENOSYS;
        goto out;
    }

	realm = list_ledata(list_apply(&auth->realml, true, cmp_handler,
				       &ch.realm));
	if (!realm) {
		realm = mem_zalloc(sizeof(*realm), realm_destructor);
		if (!realm) {
			err = ENOMEM;
			goto out;
		}

		list_append(&auth->realml, &realm->le, realm);

		err = pl_strdup(&realm->realm, &ch.realm);
		if (err)
			goto out;
	}
	else {
		if (!pl_isset(&ch.stale) || pl_strcasecmp(&ch.stale, "true")) {
			err = EAUTH;
			goto out;
		}

		realm->nonce  = mem_deref(realm->nonce);
		realm->qop    = mem_deref(realm->qop);
		realm->opaque = mem_deref(realm->opaque);
	}

	/* Curly braces are used here to avoid goto 
	from jumping over variable declaration. */
	{
		char *nonce[(ch.nonce).l];
		memcpy(nonce, (ch.nonce).p, (ch.nonce).l);
		err = auth->authh(&realm->user, &realm->pass, &realm->pass_len,
				  realm->realm, nonce, auth->arg);

		if (err)
			goto out;
	}

	realm->hdr = hdr->id;
	realm->nc  = 1;

	err = pl_strdup(&realm->nonce, &ch.nonce);

	if (pl_isset(&ch.qop))
		err |= pl_strdup(&realm->qop, &ch.qop);

	if (pl_isset(&ch.opaque))
		err |= pl_strdup(&realm->opaque, &ch.opaque);

 out:
	if (err) {
		mem_deref(realm);
		auth->err = err;
		return true;
	}

	return false;
}


/**
 * Update a SIP authentication state from a SIP message
 *
 * @param auth SIP Authentication state
 * @param msg  SIP Message
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_auth_authenticate(struct sip_auth *auth, const struct sip_msg *msg)
{
	if (!auth || !msg)
		return EINVAL;

	if (sip_msg_hdr_apply(msg, true, SIP_HDR_WWW_AUTHENTICATE,
			      auth_handler, auth))
		return auth->err;

	if (sip_msg_hdr_apply(msg, true, SIP_HDR_PROXY_AUTHENTICATE,
			      auth_handler, auth))
		return auth->err;

	return 0;
}


int sip_auth_encode(struct mbuf *mb, struct sip_auth *auth, const char *met,
		    const char *uri)
{
	struct le *le;
	int err = 0;

	if (!mb || !auth || !met || !uri)
		return EINVAL;

	for (le = auth->realml.head; le; le = le->next) {

		const uint64_t cnonce = rand_u64();
		struct realm *realm = le->data;
		uint8_t digest[MD5_SIZE];

		err = mkdigest(digest, realm, met, uri, cnonce);
		if (err)
			break;

		switch (realm->hdr) {

		case SIP_HDR_WWW_AUTHENTICATE:
			err = mbuf_write_str(mb, "Authorization: ");
			break;

		case SIP_HDR_PROXY_AUTHENTICATE:
			err = mbuf_write_str(mb, "Proxy-Authorization: ");
			break;

		default:
			continue;
		}

		err |= mbuf_printf(mb, "Digest username=\"%s\"", realm->user);
		err |= mbuf_printf(mb, ", realm=\"%s\"", realm->realm);
		err |= mbuf_printf(mb, ", nonce=\"%s\"", realm->nonce);
		err |= mbuf_printf(mb, ", uri=\"%s\"", uri);
		err |= mbuf_printf(mb, ", response=\"%w\"",
				   digest, sizeof(digest));

		if (realm->opaque)
			err |= mbuf_printf(mb, ", opaque=\"%s\"",
					   realm->opaque);

		if (realm->qop) {
			err |= mbuf_printf(mb, ", cnonce=\"%016llx\"", cnonce);
			err |= mbuf_write_str(mb, ", qop=auth");
			err |= mbuf_printf(mb, ", nc=%08x", realm->nc);
		}

		++realm->nc;

		err |= mbuf_write_str(mb, "\r\n");
		if (err)
			break;
	}

	return err;
}


/**
 * Allocate a SIP authentication state
 *
 * @param authp Pointer to allocated SIP authentication state
 * @param authh Authentication handler
 * @param arg   Handler argument
 * @param ref   True to mem_ref() argument
 *
 * @return 0 if success, otherwise errorcode
 */
int sip_auth_alloc(struct sip_auth **authp, sip_auth_h *authh,
		   void *arg, bool ref)
{
	struct sip_auth *auth;

	if (!authp)
		return EINVAL;

	auth = mem_zalloc(sizeof(*auth), auth_destructor);
	if (!auth)
		return ENOMEM;

	auth->authh = authh ? authh : dummy_handler;
	auth->arg   = ref ? mem_ref(arg) : arg;
	auth->ref   = ref;

	*authp = auth;

	return 0;
}


/**
 * Reset a SIP authentication state
 *
 * @param auth SIP Authentication state
 */
void sip_auth_reset(struct sip_auth *auth)
{
	if (!auth)
		return;

	list_flush(&auth->realml);
}
