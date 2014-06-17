/*
 * Copyright (c) 2009 Mike Belopuhov
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

#include <sys/queue.h>

/*
 * ICB packet has the following format: <length><type><data>
 * <lenght> is one byte length of the packet excluding the <lenght> byte;
 * <type> is one byte type of the packet;
 * <data> might not be null-terminated.
 */
#define ICB_MSGSIZE		 256

#define ICB_MAXGRPLEN		 32
#define ICB_MAXNICKLEN		 32
#define ICB_MAXPASSLEN		 32
#define ICB_MAXTOPICLEN		 160
#define ICB_MAXHOSTLEN		 40
#define ICB_MTABLEN		 50 /* XXX */

#define ICB_M_LOGIN		 'a'
#define ICB_M_OPEN		 'b'
#define ICB_M_PERSONAL		 'c'
#define ICB_M_STATUS		 'd'
enum {
	 STATUS_ARRIVE,
	 STATUS_BOOT,
	 STATUS_DEPART,
	 STATUS_HELP,
	 STATUS_NAME,
	 STATUS_NOBEEP,
	 STATUS_NOTIFY,
	 STATUS_SIGNON,
	 STATUS_SIGNOFF,
	 STATUS_STATUS,
	 STATUS_TOPIC,
	 STATUS_WARNING
};
#define ICB_M_ERROR		 'e'
#define ICB_M_IMPORTANT		 'f'
#define ICB_M_EXIT		 'g'
#define ICB_M_COMMAND		 'h'
#define ICB_M_CMDOUT		 'i'
enum {
	 CMDOUT_CO,
	 CMDOUT_EC,
	 CMDOUT_WG,
	 CMDOUT_WH,
	 CMDOUT_WL,
};
#define ICB_M_PROTO		 'j'
#define ICB_M_BEEP		 'k'
#define ICB_M_PING		 'l'
#define ICB_M_PONG		 'm'
#define ICB_M_NOOP		 'n'

#define ICB_M_SEP		 '\001'

struct icb_group;

struct icb_session {
	char			 nick[ICB_MAXNICKLEN];
	char			 client[ICB_MAXNICKLEN];
	char			 host[ICB_MAXHOSTLEN];
	char			 hostname[MAXHOSTNAMELEN];
	char			 buffer[ICB_MSGSIZE];
	struct event		 ev;
	struct bufferevent	*bev;
	struct icb_group	*group;
	size_t			 length;
	size_t			 rlen;
	time_t			 login;
	time_t			 last;
	int			 port;
	uint32_t		 flags;
#define SETF(t, f)		 ((t) |= (f))
#define CLRF(t, f)		 ((t) &= ~(f))
#define ISSETF(t, f)		 ((t) & (f))
#define ICB_SF_PROTOSENT	 0x0001
#define ICB_SF_LOGGEDIN		 0x0002
#define ICB_SF_NOGROUP		 0x0008
#define ICB_SF_NOBEEP		 0x0010
#define ICB_SF_NOBEEP2		 0x0020

#define ICB_SF_DNSINPROGRESS	 0x1000
#define ICB_SF_PENDINGDROP	 0x2000

	/* in-group linkage */
	LIST_ENTRY(icb_session)	 entry;
};

struct icb_group {
	char			 name[ICB_MAXGRPLEN];
	char			 mpass[ICB_MAXPASSLEN];
	char			 topic[ICB_MAXTOPICLEN];
	LIST_ENTRY(icb_group)	 entry;
	LIST_HEAD(, icb_session) sess;
	struct icb_session	*mod;
};

LIST_HEAD(icb_grlist, icb_group) groups;

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

/* cmd.c */
void *		icb_cmd_lookup(char *);

/* icb.c */
struct icb_group *
		icb_addgroup(struct icb_session *, char *, char *);
void		icb_cmdout(struct icb_session *, int, char *);
void		icb_delgroup(struct icb_group *);
void		icb_error(struct icb_session *, const char *, ...);
void		icb_init(void);
int		icb_input(struct icb_session *);
inline int	icb_ismod(struct icb_group *, struct icb_session *);
int		icb_modpermit(struct icb_session *, int);
int		icb_pass(struct icb_group *, struct icb_session *,
		    struct icb_session *);
void		icb_privmsg(struct icb_session *, char *, char *);
void		icb_remove(struct icb_session *, char *);
void		icb_sendfmt(struct icb_session *, const char *, ...);
void		icb_start(struct icb_session *);
void		icb_status(struct icb_session *, int, const char *, ...);
void		icb_status_group(struct icb_group *, struct icb_session *,
		    int, const char *, ...);
void		icb_who(struct icb_session *, struct icb_group *);
int		icb_vis(char *, const char *, size_t, int);
