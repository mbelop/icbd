/*
 * Copyright (c) 2014 Mike Belopuhov
 *
 * ASR implementation and OpenSMTPD integration are copyright
 * Copyright (c) 2008 Gilles Chehade <gilles@poolp.org>
 * Copyright (c) 2009 Jacek Masiulaniec <jacekm@dobremiasto.net>
 * Copyright (c) 2011-2012 Eric Faurot <eric@faurot.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <event.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "asr.h"

#include "icb.h"
#include "icbd.h"

struct async_event;
struct async_event *
		async_run_event(struct async *,
		    void (*)(int, struct async_res *, void *), void *);
void		dns_done(int, struct async_res *, void *);

extern int dodns;

void
dns_done(int ev __attribute__((__unused__)), struct async_res *ar, void *arg)
{
	struct icb_session *is = arg;

	if (ar->ar_gai_errno == 0) {
		syslog(LOG_DEBUG, "dns resolved %s to %s", is->host,
		    is->hostname);
		if (strncmp(is->hostname, "localhost",
		    sizeof "localhost" - 1) == 0)
			strlcpy(is->host, "unknown", ICB_MAXHOSTLEN);
		else if (strlen(is->hostname) < ICB_MAXHOSTLEN)
			strlcpy(is->host, is->hostname, ICB_MAXHOSTLEN);
	} else
		syslog(LOG_WARNING, "dns resolution failed: %s",
		    gai_strerror(ar->ar_gai_errno));
}

void
dns_rresolv(struct icb_session *is, struct sockaddr *sa)
{
	struct async *as;

	if (!dodns)
		return;

	if (verbose)
		syslog(LOG_DEBUG, "resolving: %s", is->host);

	as = getnameinfo_async(sa, sa->sa_len, is->hostname,
	    sizeof is->hostname, NULL, 0, NI_NOFQDN, NULL);
	async_run_event(as, dns_done, is);
}

/* Generic libevent glue for asr */

struct async_event {
	struct async	*async;
	struct event	 ev;
	void		(*callback)(int, struct async_res *, void *);
	void		*arg;
};

void async_event_dispatch(int, short, void *);

struct async_event *
async_run_event(struct async * async,
    void (*cb)(int, struct async_res *, void *), void *arg)
{
	struct async_event	*aev;
	struct timeval		 tv;

	aev = calloc(1, sizeof *aev);
	if (aev == NULL)
		return (NULL);
	aev->async = async;
	aev->callback = cb;
	aev->arg = arg;
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	evtimer_set(&aev->ev, async_event_dispatch, aev);
	evtimer_add(&aev->ev, &tv);
	return (aev);
}

void
async_event_dispatch(int fd __attribute__((__unused__)),
    short ev __attribute__((__unused__)), void *arg)
{
	struct async_event	*aev = arg;
	struct async_res	 ar;
	int			 r;
	struct timeval		 tv;

	while ((r = asr_async_run(aev->async, &ar)) == ASYNC_YIELD)
		aev->callback(r, &ar, aev->arg);

	event_del(&aev->ev);
	if (r == ASYNC_COND) {
		event_set(&aev->ev, ar.ar_fd,
			  ar.ar_cond == ASYNC_READ ? EV_READ : EV_WRITE,
			  async_event_dispatch, aev);
		tv.tv_sec = ar.ar_timeout / 1000;
		tv.tv_usec = (ar.ar_timeout % 1000) * 1000;
		event_add(&aev->ev, &tv);
	} else { /* ASYNC_DONE */
		aev->callback(r, &ar, aev->arg);
		free(aev);
	}
}
