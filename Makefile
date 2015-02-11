# $FreeBSD: stable/9/usr.bin/fetch/Makefile 242609 2012-11-05 12:41:55Z des $

.include <bsd.own.mk>

CC=			clang
PROG=		fetch
SRCS=		fetch.c fetch_sandbox.c
CSTD?=		c99
.ifdef DEBUG
CFLAGS+=	-DDEBUG -g
.else
CFLAGS+=  -DNDEBUG
.endif

# error checking
.if defined(NO_SANDBOX) && (defined(SANDBOX_FETCH)
                            || defined(SANDBOX_PARSE_URL)
                            || defined(SANDBOX_EPHEMERAL))
.error Sandboxing options should not be specified if NO_SANDBOX is present
.endif

.if defined(SANDBOX_FETCH) && defined(SANDBOX_PARSE_URL)
.error Both SANDBOX_FETCH and SANDBOX_PARSE_URL cannot be specified currently
.endif

.if ${MK_OPENSSL} != "no"
DPADD=		${LIBFETCH} ${LIBSSL} ${LIBCRYPTO}
LDADD=		-lfetch -lssl -lcrypto
.else
DPADD=		${LIBFETCH} ${LIBMD}
LDADD=		-lfetch -lmd
.endif
LIBFETCH_DIR?=  ../libfetch_c
LIBSEP_DIR?=  ../libsep
.ifndef NO_SANDBOX
CFLAGS+=	-I ${LIBSEP_DIR} -I ${LIBFETCH_DIR}
.ifdef SANDBOX_PARSE_URL
CFLAGS+=	-DSANDBOX_PARSE_URL
.endif
.ifdef SANDBOX_FETCH
CFLAGS+=  -DSANDBOX_FETCH
.endif
.ifdef SANDBOX_EPHEMERAL
CFLAGS+=  -DSANDBOX_EPHEMERAL
.endif
DPADD+=		${LIBSEP_DIR}
LDADD+=		-L${LIBSEP_DIR} -lsep
.else
CFLAGS+=	-DNO_SANDBOX
.endif

.include <bsd.prog.mk>
