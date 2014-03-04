PREFIX?=	/usr/local
BINDIR=		${PREFIX}/sbin
MANDIR=		${PREFIX}/man/man

PROG=		icbd
SRCS=		cmd.c dns.c icb.c icbd.c
MAN=		icbd.8

CFLAGS+=	-W -Wall -Werror
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith -Wcast-qual -Wsign-compare

DPADD=		${LIBEVENT}
LDADD=		-levent

.include <bsd.prog.mk>
