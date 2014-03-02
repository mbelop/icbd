/*
 * Copyright (c) 2009, 2010, 2013 Mike Belopuhov
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

#include <sys/param.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <event.h>

#include "icb.h"

extern int creategroups;

void icb_cmd_help(struct icb_session *, char *);
void icb_cmd_beep(struct icb_session *, char *);
void icb_cmd_boot(struct icb_session *, char *);
void icb_cmd_change(struct icb_session *, char *);
void icb_cmd_name(struct icb_session *, char *);
void icb_cmd_nobeep(struct icb_session *, char *);
void icb_cmd_personal(struct icb_session *, char *);
void icb_cmd_pass(struct icb_session *, char *);
void icb_cmd_topic(struct icb_session *, char *);
void icb_cmd_who(struct icb_session *, char *);

void *
icb_cmd_lookup(char *cmd)
{
	struct {
		const char	*cmd;
		void		(*handler)(struct icb_session *, char *);
	} cmdtab[] = {
		{ "?",		icb_cmd_help },
		{ "beep",	icb_cmd_beep },
		{ "boot",	icb_cmd_boot },
		{ "g",		icb_cmd_change },
		{ "m",		icb_cmd_personal },
		{ "msg",	icb_cmd_personal },
		{ "name",	icb_cmd_name },
		{ "nobeep",	icb_cmd_nobeep },
		{ "pass",	icb_cmd_pass },
		{ "topic",	icb_cmd_topic },
		{ "w",		icb_cmd_who },
		{ NULL,		NULL }
	};
	int i;

	for (i = 0; cmdtab[i].cmd != NULL; i++)
		if (strcasecmp(cmdtab[i].cmd, cmd) == 0)
			return (cmdtab[i].handler);
	return (NULL);
}

void
icb_cmd_help(struct icb_session *is, char *arg __attribute__((unused)))
{
	icb_status(is, STATUS_HELP, "Server supports following commands:");
	icb_status(is, STATUS_HELP, "beep boot g m name nobeep pass topic");
}

void
icb_cmd_beep(struct icb_session *is, char *arg)
{
	struct icb_group *ig = is->group;
	struct icb_session *s;

	if (strlen(arg) == 0) {
		icb_error(is, "Invalid user");
		return;
	}

	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, arg) == 0)
			break;
	}
	if (s == NULL) {
		icb_status(is, STATUS_NOTIFY, "%s is not signed on", arg);
		return;
	}

	if (ISSETF(s->flags, ICB_SF_NOBEEP | ICB_SF_NOBEEP2)) {
		icb_error(is, "User has nobeep enabled");
		if (ISSETF(s->flags, ICB_SF_NOBEEP2))
			icb_status(s, STATUS_NOBEEP,
			    "%s attempted to beep you", is->nick);
		return;
	}

	icb_sendfmt(s, "%c%s", ICB_M_BEEP, is->nick);
}

void
icb_cmd_boot(struct icb_session *is, char *arg)
{
	struct icb_group *ig;
	struct icb_session *s;

	/* to boot or not to boot, that is the question */
	ig = is->group;
	if (!icb_ismod(ig, is)) {
		icb_status(is, STATUS_NOTIFY, "Sorry, booting is a privilege "
		    "you don't possess");
		return;
	}

	/* who would be a target then? */
	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, arg) == 0)
			break;
	}
	if (s == NULL) {
		icb_status(is, STATUS_NOTIFY, "No such user");
		return;
	}

	/* okay, here we go, but first, be polite and notify a user */
	icb_status(s, STATUS_BOOT, "%s booted you", is->nick);
	icb_status_group(s->group, s, STATUS_BOOT, "%s was booted", s->nick);
	icb_drop(s, "booted");
}

void
icb_cmd_change(struct icb_session *is, char *arg)
{
	struct icb_group *ig;
	struct icb_session *s;
	int changing = 0;

	if (strlen(arg) == 0) {
		icb_error(is, "Invalid group");
		return;
	}

	LIST_FOREACH(ig, &groups, entry) {
		if (strcmp(ig->name, arg) == 0)
			break;
	}
	if (ig == NULL) {
		if (!creategroups) {
			icb_error(is, "Invalid group");
			return;
		} else {
			if ((ig = icb_addgroup(is, arg, NULL)) == NULL) {
				icb_error(is, "Can't create group");
				return;
			}
			icb_log(NULL, LOG_DEBUG, "%s created group %s",
			    is->nick, arg);
		}
	}

	/* see if we're changing to the same group */
	if (is->group && is->group == ig) {
		icb_error(is, "You are already in that group");
		return;
	}

	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, is->nick) == 0) {
			icb_error(is, "Nick is already in use");
			return;
		}
	}

	if (is->group) {
		changing = 1;
		if (icb_ismod(is->group, is))
			(void)icb_pass(is->group, is, NULL);
		LIST_REMOVE(is, entry);
		icb_status_group(is->group, NULL, STATUS_DEPART,
		    "%s (%s@%s) just left", is->nick, is->client, is->host);
	}

	is->group = ig;
	LIST_INSERT_HEAD(&ig->sess, is, entry);

	/* notify group */
	icb_status_group(ig, is, changing ? STATUS_ARRIVE : STATUS_SIGNON,
	    "%s (%s@%s) entered group", is->nick, is->client, is->host);

	/* acknowledge successful join */
	icb_status(is, STATUS_STATUS, "You are now in group %s%s", ig->name,
	    icb_ismod(ig, is) ? " as moderator" : "");

	/* send user a topic name */
	if (strlen(ig->topic) > 0)
		icb_status(is, STATUS_TOPIC, "The topic is: %s", ig->topic);
}

void
icb_cmd_name(struct icb_session *is, char *arg)
{
	struct icb_group *ig = is->group;
	struct icb_session *s;

	if (strlen(arg) == 0) {
		icb_status(is, STATUS_NAME, "Your nickname is %s",
		    is->nick);
		return;
	}
	if (strcasecmp(arg, "admin") == 0) {
		icb_error(is, "Wuff wuff!");
		return;
	}
	/* sanitize user input */
	if (strlen(arg) > ICB_MAXNICKLEN)
		arg[ICB_MAXNICKLEN - 1] = '\0';
	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, arg) == 0) {
			icb_error(is, "Nick is already in use");
			return;
		}
	}
	icb_status_group(ig, NULL, STATUS_NAME,
	    "%s changed nickname to %s", is->nick, arg);
	strlcpy(is->nick, arg, sizeof is->nick);
}

void
icb_cmd_nobeep(struct icb_session *is, char *arg)
{
	if (strlen(arg) == 0) {
		/* fail if we have verbose turned on */
		if (ISSETF(is->flags, ICB_SF_NOBEEP2)) {
			icb_error(is, "Can't toggle your nobeep status");
			return;
		}
		/* otherwise toggle the status */
		if (ISSETF(is->flags, ICB_SF_NOBEEP))
			CLRF(is->flags, ICB_SF_NOBEEP);
		else
			SETF(is->flags, ICB_SF_NOBEEP);
		icb_status(is, STATUS_NOBEEP, "No-Beep %s",
		    ISSETF(is->flags, ICB_SF_NOBEEP) ? "on" : "off");
		return;
	}

	if (strcmp(arg, "on") == 0) {
		SETF(is->flags, ICB_SF_NOBEEP);
		CLRF(is->flags, ICB_SF_NOBEEP2); /* can't be on and verbose */
		icb_status(is, STATUS_NOBEEP, "No-Beep on");
	} else if (strcmp(arg, "verbose") == 0) {
		SETF(is->flags, ICB_SF_NOBEEP2);
		CLRF(is->flags, ICB_SF_NOBEEP); /* can't be on and verbose */
		icb_status(is, STATUS_NOBEEP, "No-Beep on (verbose)");
	} else if (strcmp(arg, "off") == 0) {
		CLRF(is->flags, ICB_SF_NOBEEP | ICB_SF_NOBEEP2);
		icb_status(is, STATUS_NOBEEP, "No-Beep off");
	} else
		icb_error(is, "Invalid nobeep mode");
}

void
icb_cmd_personal(struct icb_session *is, char *arg)
{
	char *p;

	if ((p = strchr(arg, ' ')) == 0) {
		icb_error(is, "Empty message");
		return;
	}
	*p = '\0';
	icb_privmsg(is, arg, ++p);
}

void
icb_cmd_pass(struct icb_session *is, char *arg)
{
	struct icb_group *ig = is->group;
	struct icb_session *s;

	if (!ig->mod)		/* if there is no mod, let anyone grab it */
		(void)icb_pass(ig, ig->mod, is);
	else if (icb_ismod(ig, is)) {
		LIST_FOREACH(s, &ig->sess, entry) {
			if (strcmp(s->nick, arg) == 0)
				break;
		}
		if (s == NULL) {
			icb_status(is, STATUS_NOTIFY, "No such user");
			return;
		}
		(void)icb_pass(ig, ig->mod, s);
	}
}

void
icb_cmd_topic(struct icb_session *is, char *arg)
{
	struct icb_group *ig = is->group;

	if (strlen(arg) == 0) {	/* querying the topic */
		if (strlen(ig->topic) > 0)
			icb_status(is, STATUS_TOPIC, "The topic is: %s",
			    ig->topic);
		else
			icb_status(is, STATUS_TOPIC, "The topic is not set.");
	} else {		/* setting the topic */
		if (!icb_ismod(ig, is)) {
			icb_status(is, STATUS_NOTIFY, "Setting the topic is "
			    "only for moderators.");
			return;
		}
		strlcpy(ig->topic, arg, sizeof ig->topic);
		icb_status_group(ig, NULL, STATUS_TOPIC,
		    "%s changed the topic to \"%s\"", is->nick, ig->topic);
	}
}

void
icb_cmd_who(struct icb_session *is, char *arg)
{
	struct icb_group *ig;

	if (strlen(arg) == 0)
		return icb_who(is, NULL);

	LIST_FOREACH(ig, &groups, entry) {
		if (strcmp(ig->name, arg) == 0)
			break;
	}
	if (ig == NULL) {
		icb_error(is, "The group %s doesn't exist.", arg);
		return;
	}
	icb_who(is, ig);
}
