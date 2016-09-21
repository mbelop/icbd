/*
 * Copyright (c) 2014 Mike Belopuhov
 * Copyright (c) 2009 Michael Shalayeff
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
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <sysexits.h>
#include <time.h>
#include <login_cap.h>
#include <event.h>
#include <pwd.h>

#include "icb.h"
#include "icbd.h"

void logger_ioerr(struct bufferevent *, short, void *);
void logger_dispatch(struct bufferevent *, void *);
FILE *logger_open(char *);
void logger_tick(void);

struct icbd_logentry {
	char	group[ICB_MAXGRPLEN];
	char	nick[ICB_MAXNICKLEN];
	size_t	length;
};

struct {
	char	group[ICB_MAXGRPLEN];
	FILE	*fp;
} logfiles[10];
int nlogfiles;

int logger_pipe;

char file_ts[sizeof "0000-00"];
char line_ts[sizeof "00:00"];
struct event ev_tick;

extern char logprefix[PATH_MAX/2];
extern int dologging;

int
logger_init(void)
{
	struct bufferevent *bev;
	struct passwd *pw;
	int pipes[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipes) == -1) {
		syslog(LOG_ERR, "%s: socketpair: %m", __func__);
		exit(EX_OSERR);
	}

	switch (fork()) {
	case -1:
		syslog(LOG_ERR, "%s: fork: %m", __func__);
		exit(EX_OSERR);
	case 0:
		break;

	default:
		close(pipes[1]);
		logger_pipe = pipes[0];
		return (0);
	}

	setproctitle("logger");
	close(pipes[0]);

	if ((pw = getpwnam(ICBD_USER)) == NULL) {
		syslog(LOG_ERR, "%s: No passwd entry for %s", __func__,
		    ICBD_USER);
		exit(EX_NOUSER);
	}

	if (setusercontext(NULL, pw, pw->pw_uid,
	    LOGIN_SETALL & ~LOGIN_SETUSER) < 0)
		exit(EX_NOPERM);

	if (chroot(pw->pw_dir) < 0) {
		syslog(LOG_ERR, "%s: %s: %m", __func__, pw->pw_dir);
		exit(EX_UNAVAILABLE);
	}

	if (chdir("/") < 0) {
		syslog(LOG_ERR, "%s: chdir: %m", __func__);
		exit(EX_UNAVAILABLE);
	}

	chdir (ICBD_HOME);

	if (setuid(pw->pw_uid) < 0) {
		syslog(LOG_ERR, "%s: %d: %m", __func__, pw->pw_uid);
		exit(EX_NOPERM);
	}

	if (pledge("stdio cpath wpath", NULL) == -1) {
		syslog(LOG_ERR, "%s: pledge", __func__);
		exit(EX_NOPERM);
	}

	event_init();

	/* event for message processing */
	if ((bev = bufferevent_new(pipes[1], logger_dispatch, NULL,
	    logger_ioerr, NULL)) == NULL) {
		syslog(LOG_ERR, "%s: bufferevent_new: %m", __func__);
		exit(EX_UNAVAILABLE);
	}
	if (bufferevent_enable(bev, EV_READ)) {
		syslog(LOG_ERR, "%s: bufferevent_enable: %m", __func__);
		bufferevent_free(bev);
		exit(EX_UNAVAILABLE);
	}

	evtimer_set(&ev_tick, (void (*)(int, short, void *))logger_tick, NULL);
	logger_tick();
	return event_dispatch();
}

void
logger_ioerr(struct bufferevent *bev __attribute__((__unused__)), short what,
    void *arg __attribute__((__unused__)))
{
	const char *cause = NULL;

	if (what & EVBUFFER_TIMEOUT)
		cause = "timeout";
	else if (what & EVBUFFER_EOF)
		cause = "eof";
	else if (what & EVBUFFER_ERROR)
		cause = what & EVBUFFER_READ ? "read" : "write";
	syslog(LOG_ERR, "%s: %s", __func__, cause ? cause : "unknown");
	exit(EX_IOERR);
}

void
logger_dispatch(struct bufferevent *bev, void *arg __attribute__((unused)))
{
	struct icbd_logentry *e;
	static char buf[sizeof *e + ICB_MSGSIZE];
	static size_t nread = 0;
	FILE *fp = NULL;
	size_t res;
	char *m;
	int i;

	e = (struct icbd_logentry *)buf;
	m = buf + sizeof *e;

	while (EVBUFFER_LENGTH(EVBUFFER_INPUT(bev)) > 0) {
		if (nread == 0) {
			bzero(e, sizeof *e);
			/* read the log entry header */
			res = bufferevent_read(bev, &buf[0], sizeof *e);
			nread += res;
			if (nread < sizeof *e)
				return;
		}
		/* see if we got the whole header */
		if (nread < sizeof *e) {
			/* finish reading */
			res = bufferevent_read(bev, &buf[nread],
			    sizeof *e - nread);
			nread += res;
			if (nread < sizeof *e)
				return;
		}
		if (e->length >= ICB_MSGSIZE) {
			syslog(LOG_ERR, "%s: message too big: %lu", __func__,
			    e->length);
			exit(EX_DATAERR);
		}
		/* fetch the message */
		res = bufferevent_read(bev, &buf[nread],
		    e->length - (nread - sizeof *e));
		nread += res;
#ifdef DEBUG
		{
			printf("logger read %lu out of %lu:\n", res, e->length);
			for (i = 0; i < (int)res; i++)
				printf(" %02x", (unsigned char)m[i]);
			printf("\n");
		}
#endif
		if (nread - sizeof *e < e->length)
			return;
		/* terminate the buffer */
		m[MIN(nread - sizeof *e, ICB_MSGSIZE - 1)] = '\0';
		/* find the appropriate log file */
		for (i = 0; i < nlogfiles; i++)
			if (strcmp(logfiles[i].group, e->group) == 0)
				fp = logfiles[i].fp;
		if (!fp && (fp = logger_open(e->group)) == NULL)
			return;
		if (strlen(e->nick) == 0)
			fprintf(fp, "[%s] %s\n", line_ts, m);
		else
			fprintf(fp, "[%s] <%s> %s\n", line_ts, e->nick, m);
		/* get ready for the next message */
		nread = 0;
	}
}

FILE *
logger_open(char *group)
{
	char path[PATH_MAX];
	FILE *fp = NULL;

	/* make sure not to overflow the logfiles table */
	if (nlogfiles == nitems(logfiles)) {
		syslog(LOG_NOTICE, "%s: logfiles table is full", __func__);
		return (NULL);
	}
	snprintf(path, sizeof path, "%s/%s", logprefix, group);
	if (mkdir(path, 0755) < 0 && errno != EEXIST) {
		syslog(LOG_ERR, "%s: %s: %m", __func__, group);
		return (NULL);
	}
	snprintf(path, sizeof path, "%s/%s/%s", logprefix, group, file_ts);
	if ((fp = fopen(path, "a")) == NULL) {
		syslog(LOG_ERR, "%s: %s: %m", __func__, path);
		return (NULL);
	}
	setvbuf(fp, NULL, _IOLBF, 0);
	if (verbose)
		syslog(LOG_NOTICE, "%s: %s", __func__, path);
	strlcpy(logfiles[nlogfiles].group, group, ICB_MAXGRPLEN);
	logfiles[nlogfiles++].fp = fp;
	return (fp);
}

void
logger(char *group, char *nick, char *what)
{
	struct icbd_logentry e;
	struct iovec iov[2];
	const char *defgrp = "1";

	if (!dologging)
		return;

	if (strcmp(group, defgrp) == 0)
		return;

	strlcpy(e.group, group, ICB_MAXGRPLEN);
	strlcpy(e.nick, nick, ICB_MAXNICKLEN);
	e.length = strlen(what) + 1;

	iov[0].iov_base = &e;
	iov[0].iov_len = sizeof e;

	iov[1].iov_base = what;
	iov[1].iov_len = e.length;

	if (writev(logger_pipe, iov, 2) == -1)
		syslog(LOG_ERR, "%s: %m", __func__);
}

void
logger_tick(void)
{
	static int last_mon = -1, last_mday = -1;
	struct timeval tv = { 60, 0 };
	char buf[128];
	struct tm *tm;
	time_t t;
	int i;

	time(&t);
	tm = gmtime(&t);
	if (last_mon != tm->tm_mon) {
		snprintf(file_ts, sizeof file_ts, "%04d-%02d",
		    tm->tm_year + 1900, tm->tm_mon + 1);
		last_mon = tm->tm_mon;
		/* rotate log files */
		for (i = 0; i < nlogfiles; i++) {
			fclose(logfiles[i].fp);
			logfiles[i].fp = NULL;
		}
		nlogfiles = 0;
	}
	if (tm->tm_mday != last_mday) {
		strftime(buf, sizeof(buf),
		    "Today is %a %b %e %Y %H:%M %Z (%z)", tm);
		for (i = 0; i < nlogfiles; i++)
			fprintf(logfiles[i].fp, "%s\n", buf);
		last_mday = tm->tm_mday;
	}
	snprintf(line_ts, sizeof line_ts, "%02d:%02d", tm->tm_hour,
	    tm->tm_min);
	if (evtimer_add(&ev_tick, &tv) < 0) {
		syslog(LOG_ERR, "%s: evtimer_add: %m", __func__);
		exit(EX_UNAVAILABLE);
	}
}
