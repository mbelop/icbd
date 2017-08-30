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

#include <sys/types.h>
#include <sys/queue.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <vis.h>
#include <event.h>

#include "icb.h"
#include "icbd.h"

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
	icb_status(is, STATUS_HELP, "beep boot g m name nobeep pass topic w");
}

void
icb_cmd_beep(struct icb_session *is, char *arg)
{
	struct icb_group *ig = is->group;
	struct icb_session *s;
	char whom[ICB_MAXNICKLEN];

	if (strlen(arg) == 0) {
		icb_error(is, "Invalid user");
		return;
	}

	icb_vis(whom, arg, ICB_MAXNICKLEN, VIS_SP);

	/* Search in the same group first */
	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, whom) == 0)
			break;
	}
	if (s == NULL) {
		/* See if we can find someone else to beep */
		LIST_FOREACH(ig, &groups, entry) {
			if (strcmp(is->group->name, ig->name) == 0)
				continue;
			LIST_FOREACH(s, &ig->sess, entry) {
				if (strcmp(s->nick, whom) == 0)
					break;
			}
			if (s != NULL)
				break;
		}
	}
	if (s == NULL) {
		icb_status(is, STATUS_NOTIFY, "%s is not signed on", whom);
		return;
	}
	if (s == is) {
		icb_error(is, "Very funny... Not!");
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
	char whom[ICB_MAXNICKLEN];

	/* to boot or not to boot, that is the question */
	ig = is->group;
	if (!icb_ismod(ig, is)) {
		icb_status(is, STATUS_NOTIFY, "Sorry, booting is a privilege "
		    "you don't possess");
		return;
	}

	if (strlen(arg) == 0) {
		icb_error(is, "Invalid user");
		return;
	}

	icb_vis(whom, arg, ICB_MAXNICKLEN, VIS_SP);

	/* who would be a target then? */
	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, whom) == 0)
			break;
	}
	if (s == NULL) {
		icb_status(is, STATUS_NOTIFY, "No such user");
		return;
	}
	if (s == is) {
		icb_error(is, "Just quit, would you?");
		return;
	}

	/* okay, here we go, but first, be polite and notify a user */
	icb_status(s, STATUS_BOOT, "%s booted you", is->nick);
	icb_status_group(s->group, s, STATUS_BOOT, "%s was booted", s->nick);
	icbd_drop(s, "booted");
}

void
icb_cmd_change(struct icb_session *is, char *arg)
{
	struct icb_group *ig;
	struct icb_session *s;
	char group[ICB_MAXGRPLEN];
	int changing = 0;

	if (strlen(arg) == 0) {
		icb_error(is, "Invalid group name");
		return;
	}

	icb_vis(group, arg, ICB_MAXGRPLEN, VIS_SP);

	LIST_FOREACH(ig, &groups, entry) {
		if (strcmp(ig->name, group) == 0)
			break;
	}
	if (ig == NULL) {
		if (!creategroups) {
			icb_error(is, "Can't create new groups");
			return;
		} else {
			if ((ig = icb_addgroup(is, group)) == NULL) {
				icb_error(is, "Can't create group %s", group);
				return;
			}
			icbd_log(NULL, LOG_DEBUG, "%s created group %s",
			    is->nick, group);
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
	char nick[ICB_MAXNICKLEN];

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
	icb_vis(nick, arg, ICB_MAXNICKLEN, VIS_SP);
	LIST_FOREACH(s, &ig->sess, entry) {
		if (strcmp(s->nick, nick) == 0) {
			icb_error(is, "Nick is already in use");
			return;
		}
	}
	icb_status_group(ig, NULL, STATUS_NAME,
	    "%s changed nickname to %s", is->nick, nick);
	strlcpy(is->nick, nick, sizeof is->nick);
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
	char whom[ICB_MAXNICKLEN];

	if (icb_ismod(ig, is)) {
		/*
		 * we're a current group moderator, allow to relinquish
		 * the right and to pass it down to everybody else.
		 */
		if (strlen(arg) == 0) {
			/* no argument: relinquish moderator */
			(void)icb_pass(ig, ig->mod, NULL);
			return;
		}
		icb_vis(whom, arg, ICB_MAXNICKLEN, VIS_SP);
		LIST_FOREACH(s, &ig->sess, entry) {
			if (strcmp(s->nick, whom) == 0)
				break;
		}
		if (s == NULL) {
			icb_status(is, STATUS_NOTIFY, "No such user");
			return;
		}
		if (icb_pass(ig, ig->mod, s) < 0)
			icb_error(is, "Failed to pass group moderation.");
	} else {
		/*
		 * if group is moderated and we're not the moderator,
		 * but modtab is enabled, then check the permission
		 * and pass moderation if successful.  if there's no
		 * current moderator, don't enforce the modtab.
		 */
		if (!icb_modpermit(is, ig->mod ? 1 : 0)) {
			icb_error(is, "Operation not permitted.");
			return;
		}
		if (icb_pass(ig, ig->mod, is) < 0)
			icb_error(is, "Failed to acquire group moderation.");
	}
}

void
icb_cmd_topic(struct icb_session *is, char *arg)
{
	struct icb_group *ig = is->group;
	char topic[ICB_MAXTOPICLEN];

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
		icb_vis(topic, arg, ICB_MAXTOPICLEN, 0);
		strlcpy(ig->topic, topic, sizeof ig->topic);
		icb_status_group(ig, NULL, STATUS_TOPIC,
		    "%s changed the topic to \"%s\"", is->nick, ig->topic);
	}
}

void
icb_cmd_who(struct icb_session *is, char *arg)
{
	struct icb_group *ig;
	char group[ICB_MAXGRPLEN];

	while (strlen(arg) && arg[0] == '-') { /* ignore options, for now */
		/* ircII "set SHOW_CHANNEL_NAMES ON" uses /w -s */
		while(arg[0] != ' ' && arg[0] != 0)
			arg++;
		if(arg[0] == ' ')
			arg++;
	}

	if (strlen(arg) == 0)
		return icb_who(is, NULL);

	/* pidgin-icb treats '.' as the current group */
	if (strlen(arg) == 1 && arg[0] == '.') {
		icb_who(is, is->group);
		return;
	}

	icb_vis(group, arg, ICB_MAXGRPLEN, VIS_SP);
	LIST_FOREACH(ig, &groups, entry) {
		if (strcmp(ig->name, group) == 0)
			break;
	}
	if (ig == NULL) {
		icb_error(is, "The group %s doesn't exist.", group);
		return;
	}
	icb_who(is, ig);
}
