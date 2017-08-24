/*
 * Copyright (c) 2009, 2010, 2013, 2014 Mike Belopuhov
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>
#include <event.h>
#include <vis.h>

#include "icb.h"
#include "icbd.h"

struct icb_grplist groups;

extern int creategroups;
extern char srvname[NI_MAXHOST];

void   icb_command(struct icb_session *, char *, char *);
void   icb_groupmsg(struct icb_session *, char *);
int    icb_login(struct icb_session *, char *, char *, char *);
int    icb_dowho(struct icb_session *, struct icb_group *);

/*
 *  icb_init: initialize server name and a list of groups
 */
void
icb_init(void)
{
	LIST_INIT(&groups);

	if (strlen(srvname) == 0)
		(void)gethostname(srvname, sizeof srvname);
	/*
	 * NI_MAXHOST is usually greater than what we
	 * can actually send, hence truncation:
	 */
	if (strlen(srvname) > 200)
		srvname[200] = '\0';
}

/*
 *  icb_start: called upon accepting a new connection, greets new client
 */
void
icb_start(struct icb_session *is)
{
	icb_sendfmt(is, "%c%c%c%s%c%s", ICB_M_PROTO, '1', ICB_M_SEP, srvname,
	    ICB_M_SEP, "icbd");
	SETF(is->flags, ICB_SF_PROTOSENT);
}

/*
 *  icb_input: main input processing routine
 */
int
icb_input(struct icb_session *is)
{
	char *msg = is->buffer;
	int msglen = is->length;
	unsigned char type;
	char *wptr = NULL;
	int res = 0;

	is->last = getmonotime();
	type = msg[0];
	msg++;
	if (!ISSETF(is->flags, ICB_SF_LOGGEDIN) && type != ICB_M_LOGIN) {
		icb_error(is, "Not logged in");
		return (0);
	}
	switch (type) {
	case ICB_M_LOGIN: {
		char client[ICB_MAXNICKLEN];
		char nick[ICB_MAXNICKLEN];
		char group[ICB_MAXGRPLEN];
		char cmd[ICB_MAXCMDLEN];

		memset(client, 0, sizeof client);
		if (icb_token(msg, msglen, &wptr, client, ICB_MAXNICKLEN,
		    ICB_M_SEP, 1) < 0) {
			icb_error(is, "Invalid client");
			icbd_drop(is, NULL);
			return (1);
		}
		memset(nick, 0, sizeof nick);
		if (icb_token(msg, msglen, &wptr, nick, ICB_MAXNICKLEN,
		    ICB_M_SEP, 1) <= 0) {
			icb_error(is, "Invalid nick");
			icbd_drop(is, NULL);
			return (1);
		}
		memset(group, 0, sizeof group);
		if (icb_token(msg, msglen, &wptr, group, ICB_MAXGRPLEN,
		    ICB_M_SEP, 1) < 0) {
			icb_error(is, "Invalid login group");
			icbd_drop(is, NULL);
			return (1);
		}
		memset(cmd, 0, sizeof cmd);
		if (icb_token(msg, msglen, &wptr, cmd, ICB_MAXCMDLEN,
		    ICB_M_SEP, 1) < 0) {
			icb_error(is, "Invalid command");
			icbd_drop(is, NULL);
			return (1);
		}
		if (strlen(cmd) > 0 && cmd[0] == 'w') {
			icb_error(is, "Command not implemented");
			icbd_drop(is, NULL);
			return (1);
		}
		if (strlen(cmd) == 0 || strcmp(cmd, "login") != 0) {
			icb_error(is, "Malformed login packet");
			icbd_drop(is, NULL);
			return (1);
		}
		res = icb_login(is, group, nick, client);
		break;
	}
	case ICB_M_OPEN: {
		icb_groupmsg(is, msg);
		break;
	}
	case ICB_M_COMMAND: {
		char cmd[ICB_MAXCMDLEN];

		memset(cmd, 0, sizeof cmd);
		if (icb_token(msg, msglen, &wptr, cmd, ICB_MAXCMDLEN,
		    ICB_M_SEP, 1) <= 0) {
			icb_error(is, "Invalid command");
			icbd_drop(is, NULL);
			return (1);
		}
		msg = wptr;
		icb_command(is, cmd, msg);
		break;
	}
	case ICB_M_PONG: {
		icb_sendfmt(is, "%c", ICB_M_PING);
		break;
	}
	case ICB_M_PROTO:
	case ICB_M_NOOP:
		/* ignore */
		break;
	default:
		/* everything else is not valid */
		icb_error(is, "Undefined message type %u", type);
	}
	return (res);
}

/*
 *  icb_login: handles login ('a') packets
 */
int
icb_login(struct icb_session *is, char *grp, char *nick, char *client)
{
	const char *defgrp = "1";
	struct icb_group *ig;
	struct icb_session *s;
	char group[ICB_MAXGRPLEN];

	if (!nick || strlen(nick) == 0 ||
	    icb_vis(is->nick, nick, ICB_MAXNICKLEN, VIS_SP)) {
		icb_error(is, "Invalid nick");
		icbd_drop(is, NULL);
		return (1);
	}
	if (!grp || strlen(grp) == 0)
		strlcpy(group, defgrp, ICB_MAXGRPLEN);
	else
		icb_vis(group, grp, ICB_MAXGRPLEN, VIS_SP);
	LIST_FOREACH(ig, &groups, entry) {
		if (strcmp(ig->name, group) == 0)
			break;
	}
	if (ig == NULL) {
		if (!creategroups) {
			icb_error(is, "Can't create new groups", group);
			icbd_drop(is, NULL);
			return (1);
		} else {
			if ((ig = icb_addgroup(is, group)) == NULL) {
				icb_error(is, "Can't create group %s", group);
				return (0);
			}
			icbd_log(NULL, LOG_DEBUG, "%s created group %s",
			    is->nick, group);
		}
	}
	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, is->nick) == 0) {
			icb_error(is, "Nick is already in use");
			icbd_drop(is, NULL);
			return (1);
		}
	}

	if (client && strlen(client) > 0)
		icb_vis(is->client, client, sizeof is->client, VIS_SP);
	else
		strlcpy(is->client, is->nick, sizeof is->client);
	is->group = ig;
	is->login = time(NULL);
	is->last = getmonotime();

	/* notify group */
	icb_status_group(ig, NULL, STATUS_SIGNON, "%s (%s@%s) entered group",
	    is->nick, is->client, is->host);

	CLRF(is->flags, ICB_SF_PROTOSENT);
	SETF(is->flags, ICB_SF_LOGGEDIN);

	LIST_INSERT_HEAD(&ig->sess, is, entry);

	/* acknowledge successful login */
	icb_sendfmt(is, "%c", ICB_M_LOGIN);

	/* notify user */
	icb_status(is, STATUS_STATUS, "You are now in group %s%s", ig->name,
	    icb_ismod(ig, is) ? " as moderator" : "");

	/* send user a topic name */
	if (strlen(ig->topic) > 0)
		icb_status(is, STATUS_TOPIC, "Topic for %s is \"%s\"",
		    ig->name, ig->topic);
	return (0);
}

/*
 *  icb_groupmsg: handles open message ('b') packets
 */
void
icb_groupmsg(struct icb_session *is, char *msg)
{
	char buf[ICB_MSGSIZE];
	struct icb_group *ig = is->group;
	struct icb_session *s;
	int res, buflen;

	if (strlen(msg) == 0) {
		icb_error(is, "Empty message");
		return;
	}

	do {
		res = snprintf(&buf[1], sizeof buf - 1, "%c%s%c%s", ICB_M_OPEN,
		    is->nick, ICB_M_SEP, msg);
		if (res < 0) {
			icbd_log(is, LOG_ERR, "Format error in %s", __func__);
			return;
		}
		/* res doesn't include the terminating NUL */
		buflen = MIN((size_t)res + 1, sizeof buf - 1);
		buf[0] = buflen;

		logger(ig->name, is->nick, msg);

		LIST_FOREACH(s, &ig->sess, entry) {
			if (s == is)
				continue;
			icbd_send(s, buf, buflen + 1);
		}

		msg += buflen - 1;
	} while (res > buflen - 1);
}

/*
 *  icb_privmsg: handles personal message ('c') packets
 */
void
icb_privmsg(struct icb_session *is, char *to, char *msg)
{
	struct icb_group *ig = is->group;
	struct icb_session *s;
	char buf[ICB_MSGSIZE];
	char whom[ICB_MAXNICKLEN];
	int res, buflen;

	icb_vis(whom, to, ICB_MAXNICKLEN, VIS_SP);

	/* try home group first */
	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, whom) == 0)
			break;
	}
	if (!s) {
		/* try all groups until the first match */
		LIST_FOREACH(ig, &groups, entry) {
			LIST_FOREACH(s, &ig->sess, entry) {
				if (strcmp(s->nick, whom) == 0)
					break;
			}
			if (s)
				break;
		}
		if (!s) {
			icb_error(is, "No such user %s", whom);
			return;
		}
	}

	do {
		res = snprintf(&buf[1], sizeof buf - 1, "%c%s%c%s",
		    ICB_M_PERSONAL, is->nick, ICB_M_SEP, msg);
		if (res < 0) {
			icbd_log(is, LOG_ERR, "Format error in %s", __func__);
			return;
		}
		/* res doesn't include the terminating NUL */
		buflen = MIN((size_t)res + 1, sizeof buf - 1);
		buf[0] = buflen;

		icbd_send(s, buf, buflen + 1);

		msg += buflen - 1;
	} while (res > buflen - 1);
}

/*
 *  icb_command: handles command ('h') packets
 */
void
icb_command(struct icb_session *is, char *cmd, char *arg)
{
	void (*handler)(struct icb_session *, char *);
	char command[ICB_MAXCMDLEN];

	icb_vis(command, cmd, sizeof command, VIS_SP);

	if ((handler = icb_cmd_lookup(command)) == NULL) {
		icb_error(is, "Unsupported command: %s", command);
		return;
	}
	handler(is, arg);
}

/*
 *  icb_cmdout: sends out command output ('i') packets, called from the
 *              command handlers
 */
void
icb_cmdout(struct icb_session *is, int type, char *outmsg)
{
	char *otype = NULL;

	switch (type) {
	case CMDOUT_CO:
		otype = "co";
		break;
	case CMDOUT_EC:
		otype = "ec";
		break;
	case CMDOUT_WG:
		otype = "wg";
		break;
	case CMDOUT_WH:
		otype = "wh";
		break;
	case CMDOUT_WL:
		otype = "wl";
		break;
	default:
		icbd_log(is, LOG_ERR, "unknown cmdout type %d", type);
		return;
	}
	if (outmsg)
		icb_sendfmt(is, "%c%s%c%s", ICB_M_CMDOUT, otype, ICB_M_SEP,
		    outmsg);
	else
		icb_sendfmt(is, "%c%s", ICB_M_CMDOUT, otype);
}

/*
 *  icb_status: sends a status message ('d') to the client
 */
void
icb_status(struct icb_session *is, int type, const char *fmt, ...)
{
	va_list ap;
	char buf[ICB_MSGSIZE];
	int res, buflen = 1;
	static const struct {
		int		 type;
		const char	*msg;
	} msgtab[] = {
		{ STATUS_ARRIVE,	"Arrive" },
		{ STATUS_BOOT,		"Boot" },
		{ STATUS_DEPART,	"Depart" },
		{ STATUS_HELP,		"Help" },
		{ STATUS_NAME,		"Name" },
		{ STATUS_NOBEEP,	"No-Beep" },
		{ STATUS_NOTIFY,	"Notify" },
		{ STATUS_SIGNON,	"Sign-on" },
		{ STATUS_SIGNOFF,	"Sign-off" },
		{ STATUS_STATUS,	"Status" },
		{ STATUS_TOPIC,		"Topic" },
		{ STATUS_WARNING,	"Warning" },
		{ 0,			NULL }
	};

	if (type < 0 || type > (int)nitems(msgtab) - 1)
		return;
	res = snprintf(&buf[1], sizeof buf - 1, "%c%s%c", ICB_M_STATUS,
	    msgtab[type].msg, ICB_M_SEP);
	if (res < 0) {
		icbd_log(NULL, LOG_ERR, "Format error in %s", __func__);
		return;
	}
	buflen += MIN((size_t)res, sizeof buf - 1);
	if ((size_t)buflen >= sizeof buf) {
		icbd_log(NULL, LOG_ERR, "Status buffer too small");
		return;
	}
	va_start(ap, fmt);
	res = vsnprintf(&buf[buflen], sizeof buf - buflen, fmt, ap);
	va_end(ap);
	if (res < 0) {
		icbd_log(NULL, LOG_ERR, "Format error in %s", __func__);
		return;
	}
	buflen += MIN((size_t)res, sizeof buf - buflen);
	buf[0] = buflen;
	icbd_send(is, buf, buflen + 1);
}

/*
 *  icb_status: sends a status message ('d') to the group except of the
 *              "ex" if it's not NULL
 */
void
icb_status_group(struct icb_group *ig, struct icb_session *ex, int type,
    const char *fmt, ...)
{
	char buf[ICB_MSGSIZE - 10]; /* truncate to make sure all fits */
	va_list ap;
	struct icb_session *s;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof buf, fmt, ap);
	LIST_FOREACH(s, &ig->sess, entry) {
		if (ex && s == ex)
			continue;
		icb_status(s, type, buf);
	}
	logger(ig->name, "", buf);
	icbd_log(NULL, LOG_DEBUG, "%s", buf);
	va_end(ap);
}

/*
 *  icb_error: sends an error message ('e') to the client
 */
void
icb_error(struct icb_session *is, const char *fmt, ...)
{
	char buf[ICB_MSGSIZE];
	va_list ap;
	int res, buflen = 1;

	va_start(ap, fmt);
	res = vsnprintf(&buf[2], sizeof buf - 2, fmt, ap);
	va_end(ap);
	if (res < 0) {
		icbd_log(NULL, LOG_ERR, "Format error");
		return;
	}
	buflen += MIN((size_t)res, sizeof buf - 2);
	buf[0] = ++buflen; /* account for ICB_M_ERROR */
	buf[1] = ICB_M_ERROR;
	icbd_send(is, buf, buflen + 1);
	icbd_log(is, LOG_DEBUG, "%s", buf + 2);
}

/*
 *  icb_remove: removes a session from the associated group
 */
void
icb_remove(struct icb_session *is, char *reason)
{
	if (is->group) {
		if (icb_ismod(is->group, is))
			(void)icb_pass(is->group, is, NULL);
		LIST_REMOVE(is, entry);
		if (reason)
			icb_status_group(is->group, NULL, STATUS_SIGNOFF,
			    "%s (%s@%s) just left: %s", is->nick, is->client,
			    is->host, reason);
		else
			icb_status_group(is->group, NULL, STATUS_SIGNOFF,
			    "%s (%s@%s) just left", is->nick, is->client,
			    is->host);
		is->group = NULL;
	}
}

/*
 *  icb_addgroup: adds a new group to the list
 */
struct icb_group *
icb_addgroup(struct icb_session *is, char *name)
{
	struct icb_group *ig;

	if ((ig = calloc(1, sizeof *ig)) == NULL)
		return (NULL);
	strlcpy(ig->name, name, sizeof ig->name);
	if (is)
		ig->mod = is;
	LIST_INIT(&ig->sess);
	LIST_INSERT_HEAD(&groups, ig, entry);
	return (ig);
}

#ifdef notused
/*
 *  icb_delgroup: removes a group from the list
 */
void
icb_delgroup(struct icb_group *ig)
{
	struct icb_session *s;

	/* well, i guess we should kick out participants! ;-) */
	LIST_FOREACH(s, &ig->sess, entry) {
		icb_status(s, STATUS_WARNING, "Group dismissed");
		s->group = NULL;
	}
	LIST_REMOVE(ig, entry);
	bzero(ig, sizeof ig);	/* paranoic thing, obviously */
	free(ig);
}
#endif

/*
 *  icb_dowho: a helper function that sends out a group header as a command
 *             output and user information in the "wl" format
 */
int
icb_dowho(struct icb_session *is, struct icb_group *ig)
{
	char buf[ICB_MSGSIZE - 10]; /* truncate to make sure all fits */
	struct icb_session *s;
	time_t now;
	int nusers = 0;

	now = getmonotime();
	icb_cmdout(is, CMDOUT_CO, " ");
	snprintf(buf, sizeof buf, "Group: %-8s (%cvl) Mod: %-13s Topic: %s",
	    ig->name, ig->mod ? 'm' : 'p', ig->mod ? ig->mod->nick : "(None)",
	    strlen(ig->topic) > 0 ? ig->topic : "(None)");
	icb_cmdout(is, CMDOUT_CO, buf);
	LIST_FOREACH(s, &ig->sess, entry) {
		(void)snprintf(buf, sizeof buf,
		    "%c%c%s%c%lld%c0%c%lld%c%s%c%s%c%s",
		    icb_ismod(ig, s) ? 'm' : ' ', ICB_M_SEP,
		    s->nick, ICB_M_SEP, now - s->last,
		    ICB_M_SEP, ICB_M_SEP, s->login, ICB_M_SEP,
		    s->client, ICB_M_SEP, s->host, ICB_M_SEP, " ");
		icb_cmdout(is, CMDOUT_WL, buf);
		nusers++;
	}
	return (nusers);
}

/*
 *  icb_who: sends a list of users of either the specified group or all
 *           groups found on the server
 */
void
icb_who(struct icb_session *is, struct icb_group *ig)
{
	char buf[ICB_MSGSIZE - 10]; /* truncate to make sure all fits */
	struct icb_group *g;

	if (!ig) {
		int nusers = 0, ngroups = 0;

		LIST_FOREACH(g, &groups, entry) {
			nusers += icb_dowho(is, g);
			ngroups++;
		}
		if (nusers > 0) {
			(void)snprintf(buf, sizeof buf,
			    "Total: %d %s in %d %s",
			    nusers, nusers > 1 ? "users" : "user",
			    ngroups, ngroups > 1 ? "groups" : "group");
		} else
			(void)snprintf(buf, sizeof buf, "No users found.");
		icb_cmdout(is, CMDOUT_CO, buf);
	} else
		(void)icb_dowho(is, ig);
}

/*
 *  icb_ismod: checks whether group is moderated by "is"
 */
int
icb_ismod(struct icb_group *ig, struct icb_session *is)
{
	return (ig->mod == is);
}

/*
 *  icb_modpermit: checks user against the moderators table if it has
 *                 been populated
 */
int
icb_modpermit(struct icb_session *is, int enforce)
{
	extern char modtab[ICB_MTABLEN][ICB_MAXNICKLEN];
	extern int modtabcnt;

	icbd_modupdate();
	if ((enforce ? 0 : modtabcnt == 0) ||
	    bsearch(is->nick, modtab, modtabcnt, ICB_MAXNICKLEN,
	    (int (*)(const void *, const void *))strcmp))
		return (1);
	return (0);
}

/*
 *  icb_pass: passes moderation of group "ig" from "from" to "to",
 *            returns -1 if "from" is not a moderator, 1 if passed
 *            to "to" and 0 otherwise (no moderator or passed to the
 *            internal bot)
 */
int
icb_pass(struct icb_group *ig, struct icb_session *from,
    struct icb_session *to)
{
	if (ig->mod && ig->mod != from)
		return (-1);
	if (!from && !to)
		return (-1);
	ig->mod = to;
	if (to)
		icb_status(to, STATUS_NOTIFY, "%s just passed you moderation"
		    " of %s", from ? from->nick : "server", ig->name);
	icb_status_group(ig, to, STATUS_NOTIFY, "%s has passed moderation "
	    "to %s", from ? from->nick : "server", to ? to->nick : "server");
	return (1);
}

/*
 *  icb_sendfmt: formats a string and sends it over
 */
void
icb_sendfmt(struct icb_session *is, const char *fmt, ...)
{
	char buf[ICB_MSGSIZE];
	va_list ap;
	int res, buflen = 1;

	va_start(ap, fmt);
	res = vsnprintf(&buf[1], sizeof buf - 1, fmt, ap);
	va_end(ap);
	if (res < 0) {
		icbd_log(NULL, LOG_ERR, "Format error in %s", __func__);
		return;
	}
	buflen += MIN((size_t)res + 1, sizeof buf - 1);
	buf[0] = buflen;
	icbd_send(is, buf, buflen + 1);
}

/*
 *  icb_token: copies a sequence of characters delimited by the 'sep' character
 *             from the source buffer 'buf' at offset indicated by 'bufptr' to
 *             the destination buffer 'dst' and sets 'bufptr' to the next byte
 *             after 'sep'.
 */
int
icb_token(char *buf, int len, char **bufptr, char *dst, int dstlen, int sep,
    int trim)
{
	char *start;
	int i, ret;

	if (buf == NULL || len <= 0 || dst == NULL || dstlen <= 0)
		return (0);
	if (*bufptr == NULL)
		*bufptr = buf;
	start = *bufptr;
	for (i = *bufptr - buf; i < len; i++, (*bufptr)++) {
		if (**bufptr == sep || **bufptr == '\0') {
			/* copy and null terminate the token */
			ret = strlcpy(dst, start,
			    MIN(*bufptr - start + 1, dstlen));
			if (**bufptr != '\0')
				(*bufptr)++;
			if (ret > 0 && trim)
				ret = icb_trim(dst, dstlen);
			return (ret);
		}
	}
	/*
	 * Reached the end of the buffer without finding a field separator
	 * nor the end of line character.  If we have advanced our pointer
	 * we should copy the resulting single field out.
	 */
	if (*bufptr - start > 0) {
		ret = strlcpy(dst, start, MIN(*bufptr - start + 1, dstlen));
		if (ret > 0 && trim)
			ret = icb_trim(dst, dstlen);
		return (ret);
	}
	return (0);
}

/*
 *  icb_trim: trims trailing whitespace
 */
int
icb_trim(char *buf, int len)
{
	char *p = buf;
	int i;

	for (i = 0; i < len && *p != '\0'; i++)
		p++;
	if (*p == '\0' && p - buf > 0)
		p--;
	while (p >= buf && isspace(*p)) {
		*p = '\0';
		i--;
		if (p > buf)
			p--;
	}
	return (i);
}

/*
 *  icb_vis: strnvis-like function that escapes percentages as well
 */
int
icb_vis(char *dst, const char *src, size_t dstsize, int flags)
{
	int si, di, td;

	for (si = 0, di = 0; (size_t)di < dstsize - 1 && src[si] != '\0';
	    si++, di++) {
		if (src[si] == '%') {
			if ((size_t)di + 1 >= dstsize - 1)
				break;
			dst[di++] = '%';
			dst[di] = '%';
		} else if (src[si] == ' ' && flags & VIS_SP)
			dst[di] = '_';
		else if (isgraph(src[si]) || src[si] == ' ')
			dst[di] = src[si];
		else {
			td = snprintf(&dst[di], dstsize - di,
			    "\\%03o", (unsigned char)src[si]);
			if (td == -1 || (size_t)td >= dstsize - di)
				break;
			di += td - 1;
		}
	}
	dst[MIN((size_t)di, dstsize - 1)] = '\0';
	return (0);
}
