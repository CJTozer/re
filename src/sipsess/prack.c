/**
 * @file prack.c  SIP Session PRACK
 *
 * Copyright (C) 2010 Creytiv.com
 */
#include <re_types.h>
#include <re_mem.h>
#include <re_mbuf.h>
#include <re_sa.h>
#include <re_list.h>
#include <re_hash.h>
#include <re_fmt.h>
#include <re_uri.h>
#include <re_tmr.h>
#include <re_msg.h>
#include <re_sip.h>
#include <re_sipsess.h>
#include "sipsess.h"

void sipsess_prack(struct sipsess *sess, const struct sip_msg *msg)
{
	const struct sip_hdr *rseq;
	/* TODO maybe store RSeq */
	/* TODO will this do retransmission? */
	rseq = sip_msg_hdr(msg, SIP_HDR_RSEQ);
	if (rseq != NULL) {
		sip_drequestf(&sess->req, sess->sip, true, "PRACK",
			      sess->dlg, 0, sess->auth,
			      NULL, NULL, sess,
			      "RAck: %b %u %b\r\n"
			      "Content-Length: 0\r\n"
			      "\r\n",
			      rseq->val, msg->cseq.num, msg->cseq.met);
	}
}
