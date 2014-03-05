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

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
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

void logger_dispatch(int, short, void *);
FILE *logger_open(char *);
void logger_tick(int, short, void *);
void logger_setts(void);

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
char line_ts[sizeof "[00:00] "];
struct event ev_tick;

extern char logprefix[MAXPATHLEN/2];
extern int dologging;

int
logger_init(void)
{
	static struct event ev;
	struct passwd *pw;
	struct timeval tv = { 60, 0 };
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
		logger_pipe = pipes[0];
		return (0);
	}

	setproctitle("logger");
	close(pipes[0]);

	if ((pw = getpwnam(ICBD_USER)) == NULL) {
		syslog(LOG_ERR, "No passwd entry for %s", ICBD_USER);
		exit(EX_NOUSER);
	}

	if (setusercontext(NULL, pw, pw->pw_uid,
	    LOGIN_SETALL & ~LOGIN_SETUSER) < 0)
		exit(EX_NOPERM);

	if (chroot(pw->pw_dir) < 0) {
		syslog(LOG_ERR, "%s: %m", pw->pw_dir);
		exit(EX_UNAVAILABLE);
	}

	if (chdir("/") < 0) {
		syslog(LOG_ERR, "chdir: %m");
		exit(EX_UNAVAILABLE);
	}

	if (setuid(pw->pw_uid) < 0) {
		syslog(LOG_ERR, "%d: %m", pw->pw_uid);
		exit(EX_NOPERM);
	}

	event_init();

	/* event for message processing */
	event_set(&ev, pipes[1], EV_READ | EV_PERSIST, logger_dispatch, NULL);
	if (event_add(&ev, NULL) < 0) {
		syslog(LOG_ERR, "event_add: %m");
		exit (EX_UNAVAILABLE);
	}

	/* event for the tick */
	evtimer_set(&ev_tick, logger_tick, NULL);
	if (evtimer_add(&ev_tick, &tv) < 0) {
		syslog(LOG_ERR, "evtimer_add: %m");
		exit (EX_UNAVAILABLE);
	}
	logger_setts();
	return event_dispatch();
}

void
logger_dispatch(int fd, short event, void *arg __attribute__((unused)))
{
	char buf[ICB_MSGSIZE];
	struct icbd_logentry e;
	struct iovec iov[2];
	FILE *fp = NULL;
	int i;

	if (event != EV_READ)
		return;

	bzero(&e, sizeof e);
	iov[0].iov_base = &e;
	iov[0].iov_len = sizeof e;

	iov[1].iov_base = buf;
	iov[1].iov_len = sizeof buf;

	if (readv(fd, iov, 2) < (ssize_t)sizeof e) {
		syslog(LOG_ERR, "logger read: %m");
		exit(EX_DATAERR);
	}

	/* XXX */
	if (iov[1].iov_len < e.length) {
		syslog(LOG_ERR, "logger read %lu out of %lu",
		    iov[1].iov_len, e.length);
	}

	for (i = 0; i < nlogfiles; i++)
		if (strcmp(logfiles[i].group, e.group) == 0)
			fp = logfiles[i].fp;
	if (!fp && (fp = logger_open(e.group)) == NULL)
		return;
	if (strlen(e.nick) == 0)
		fprintf(fp, "%s%s\n", line_ts, buf);
	else
		fprintf(fp, "%s<%s> %s\n", line_ts, e.nick, buf);
}

FILE *
logger_open(char *group)
{
	char path[MAXPATHLEN];
	FILE *fp = NULL;

	snprintf(path, sizeof path, "%s/%s", logprefix, group);
	if (mkdir(path, 0755) < 0 && errno != EEXIST) {
		syslog(LOG_ERR, "%s: %m", group);
		return (NULL);
	}
	snprintf(path, sizeof path, "%s/%s/%s", logprefix, group, file_ts);
	if ((fp = fopen(path, "a")) == NULL) {
		syslog(LOG_ERR, "%s: %m", path);
		return (NULL);
	}
	setvbuf(fp, NULL, _IOLBF, 0);
	if (verbose)
		syslog(LOG_DEBUG, "logger_open: %s", path);
	strlcpy(logfiles[nlogfiles].group, group, ICB_MAXGRPLEN);
	logfiles[nlogfiles++].fp = fp;
	return (fp);
}

void
logger(char *group, char *nick, char *what)
{
	struct icbd_logentry e;
	struct iovec iov[2];

	if (!dologging)
		return;

	strlcpy(e.group, group, ICB_MAXGRPLEN);
	strlcpy(e.nick, nick, ICB_MAXNICKLEN);
	e.length = strlen(what) + 1;

	iov[0].iov_base = &e;
	iov[0].iov_len = sizeof e;

	iov[1].iov_base = what;
	iov[1].iov_len = e.length;

	if (writev(logger_pipe, iov, 2) == -1)
		syslog(LOG_ERR, "logger write: %m");
}

void
logger_tick(int fd __attribute__((unused)), short event __attribute__((unused)),
    void *arg __attribute__((unused)))
{
	struct timeval tv = { 60, 0 };

	logger_setts();
	if (evtimer_add(&ev_tick, &tv) < 0) {
		syslog(LOG_ERR, "evtimer_add: %m");
		exit (EX_UNAVAILABLE);
	}
}

void
logger_setts(void)
{
	struct tm *tm;
	time_t t;

	time(&t);
	tm = gmtime(&t);
	snprintf(file_ts, sizeof file_ts, "%04d-%02d", tm->tm_year + 1900,
	    tm->tm_mon + 1);
	snprintf(line_ts, sizeof line_ts, "[%02d:%02d] ", tm->tm_hour,
	    tm->tm_min);
}
