/*
 * Copyright (c) 2014 Mike Belopuhov
 * Copyright (c) 2009 Michael Shalayeff
 * All rights reserved.
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

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sysexits.h>
#include <login_cap.h>
#include <event.h>
#include <pwd.h>
#include <netdb.h>

#include "icb.h"
#include "icbd.h"

void dns_dispatch(int, short, void *);
void dns_done(int, short, void *);
int dns_pipe;

struct icbd_dnsquery {
	uint64_t			sid;
	union {
		struct sockaddr_storage	req;
		char			rep[MAXHOSTNAMELEN];
	} u;
};

int
dns_init(void)
{
	static struct event ev;
	struct passwd *pw;
	int pipes[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipes) == -1) {
		syslog(LOG_ERR, "socketpair: %m");
		exit(EX_OSERR);
	}

	switch (fork()) {
	case -1:
		syslog(LOG_ERR, "fork: %m");
		exit(EX_OSERR);
	case 0:
		break;

	default:
		close(pipes[1]);
		dns_pipe = pipes[0];

		/* event for the reply */
		event_set(&ev, dns_pipe, EV_READ | EV_PERSIST,
		    dns_done, NULL);
		if (event_add(&ev, NULL) < 0) {
			syslog(LOG_ERR, "event_add: %m");
			exit (EX_UNAVAILABLE);
		}
		return (0);
	}

	setproctitle("dns resolver");
	close(pipes[0]);

	if ((pw = getpwnam(ICBD_USER)) == NULL) {
		syslog(LOG_ERR, "No passwd entry for %s", ICBD_USER);
		exit(EX_NOUSER);
	}

	if (setusercontext(NULL, pw, pw->pw_uid,
	    LOGIN_SETALL & ~LOGIN_SETUSER) < 0)
		exit(EX_NOPERM);

	if (setuid(pw->pw_uid) < 0) {
		syslog(LOG_ERR, "%d: %m", pw->pw_uid);
		exit(EX_NOPERM);
	}

	if (chdir("/") < 0) {
		syslog(LOG_ERR, "chdir: %m");
		exit(EX_UNAVAILABLE);
	}

	event_init();

	/* event for the request */
	event_set(&ev, pipes[1], EV_READ | EV_PERSIST, dns_dispatch, NULL);
	if (event_add(&ev, NULL) < 0) {
		syslog(LOG_ERR, "event_add: %m");
		exit (EX_UNAVAILABLE);
	}

	return event_dispatch();
}

void
dns_dispatch(int fd, short event, void *arg __attribute__((unused)))
{
	char host[NI_MAXHOST];
	struct sockaddr *sa;
	struct icbd_dnsquery q;
	int gerr;

	arg = NULL;
	if (event != EV_READ)
		return;

	if (read(fd, &q, sizeof q) != sizeof q) {
		syslog(LOG_ERR, "dns read: %m");
		exit(1);
	}

	sa = (struct sockaddr *)&q.u.req;
	if ((gerr = getnameinfo(sa, sa->sa_len,
	    host, sizeof host, NULL, 0, NI_NOFQDN))) {
		syslog(LOG_ERR, "getnameinfo: %s", gai_strerror(gerr));
		return;
	}

	if (verbose)
		syslog(LOG_DEBUG, "dns_dispatch: resolved %s", host);

	memcpy(&q.u.rep, host, sizeof host);
	if (write(fd, &q, sizeof q) != sizeof q)
		syslog(LOG_ERR, "dns write: %m");
}

void
dns_done(int fd, short event, void *arg __attribute__((unused)))
{
	struct icb_session *is;
	struct icbd_dnsquery q;

	if (event != EV_READ)
		return;

	if (read(fd, &q, sizeof q) != sizeof q) {
		syslog(LOG_ERR, "read: %m");
		return;
	}

	if ((is = icbd_session_lookup(q.sid)) == NULL) {
		syslog(LOG_ERR, "failed to find session %llu", q.sid);
		return;
	}

	memcpy(is->host, q.u.rep, MAXHOSTNAMELEN);
	is->host[sizeof is->host - 1] = '\0';

	if (verbose)
		syslog(LOG_DEBUG, "icbd_dns: resolved %s", is->host);
}

int
dns_rresolv(struct icb_session *is, struct sockaddr_storage *ss)
{
	struct icbd_dnsquery q;

	if (verbose)
		syslog(LOG_DEBUG, "resolving: %s", is->host);

	memset(&q, 0, sizeof q);
	q.sid = is->id;
	memcpy(&q.u.req, ss, sizeof *ss);
	if (write(dns_pipe, &q, sizeof q) != sizeof q) {
		syslog(LOG_ERR, "write: %m");
		exit (EX_OSERR);
	}

	return 0;
}
