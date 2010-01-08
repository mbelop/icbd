/*
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

#ifndef lint
static const char rcsid[] = "$ABSD: dns.c,v 1.2 2010/01/03 01:30:00 kmerz Exp $";
#endif /* not lint */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
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
int dns_pipe;

int
icbd_dns_init(void)
{
	struct event	ev;
	int		pipe[2];
	struct passwd	*pw;

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe) == -1) {
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
		close(pipe[1]);
		dns_pipe = pipe[0];
		return (0);
	}

	setproctitle("dns resolver");
	close(pipe[0]);

	if ((pw = getpwnam(ICBD_USER)) == NULL) {
		syslog(LOG_ERR, "No passwd entry for %s", ICBD_USER);
		exit(EX_NOUSER);
	}
	if (setusercontext(NULL, pw, pw->pw_uid,
	    LOGIN_SETALL & ~LOGIN_SETUSER) < 0) {
		syslog(LOG_ERR, "%s:%m", pw->pw_name);
		exit(EX_NOPERM);
	}
	if (setuid(pw->pw_uid) < 0) {
		syslog(LOG_ERR, "%d:%m", pw->pw_uid);
		exit(EX_NOPERM);
	}
	if (chdir("/") < 0) {
		syslog(LOG_ERR, "chdir: %m");
		exit(EX_UNAVAILABLE);
	}

	event_init();

	event_set(&ev, pipe[1], EV_READ | EV_PERSIST, dns_dispatch, NULL);
	if (event_add(&ev, NULL) < 0) {
		syslog(LOG_ERR, "event_add: %m");
		exit (EX_UNAVAILABLE);
	}

	return event_dispatch();
}

void
dns_dispatch(int fd, short event, void *arg)
{
	char host[NI_MAXHOST];
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	int gerr, ss_len = sizeof ss;

	arg = NULL;
	if (event != EV_READ)
		return;

	if (verbose)
		syslog(LOG_DEBUG, "dns_dispatch");

	if (read(fd, &ss, ss_len) != ss_len) {
		syslog(LOG_ERR, "dns read: %m");
		exit(1);
	}

	if ((gerr = getnameinfo(sa, sa->sa_len,
	    host, sizeof host, NULL, 0, NI_NOFQDN))) {
		syslog(LOG_ERR, "getnameinfo: %s", gai_strerror(gerr));
		write(fd, host, sizeof host);
		return;
	}

	if (verbose)
		syslog(LOG_DEBUG, "dns_dispatch: resolved %s", host);

	if (write(fd, host, sizeof host) != sizeof host)
		syslog(LOG_ERR, "dns write: %m");
}

int
dns_rresolv(struct icb_session *is, struct sockaddr_storage *ss)
{
	/* one-shot event for the reply */
	event_set(&is->ev, dns_pipe, EV_READ, icbd_dns, is);
	if (event_add(&is->ev, NULL) < 0) {
		syslog(LOG_ERR, "event_add: %m");
		exit (EX_UNAVAILABLE);
	}

	inet_ntop(ss->ss_family, ss->ss_family == AF_INET ?
	    (void *)&((struct sockaddr_in *)ss)->sin_addr :
	    (void *)&((struct sockaddr_in6 *)ss)->sin6_addr,
	    is->host, sizeof is->host);

	if (verbose)
		syslog(LOG_DEBUG, "resolving: %s", is->host);

	if (write(dns_pipe, ss, sizeof *ss) != sizeof *ss) {
		syslog(LOG_ERR, "write: %m");
		exit (EX_OSERR);
	}

	return 0;
}
