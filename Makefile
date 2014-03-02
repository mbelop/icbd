PREFIX?=/usr/local
BINDIR=	${PREFIX}/sbin
MANDIR=	${PREFIX}/man/man

PROG=	icbd
SRCS=	cmd.c dns.c icb.c icbd.c
MAN=	icbd.8

CFLAGS+=-W -Wall -Werror

DPADD=	${LIBEVENT}
LDADD=	-levent

.include <bsd.prog.mk>
