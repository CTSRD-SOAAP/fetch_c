# $FreeBSD: stable/9/usr.bin/fetch/Makefile 242609 2012-11-05 12:41:55Z des $

.include <bsd.own.mk>

PROG=		fetch
CSTD?=		c99
.if ${MK_OPENSSL} != "no"
DPADD=		${LIBFETCH} ${LIBSSL} ${LIBCRYPTO}
LDADD=		-lfetch -lssl -lcrypto
.else
DPADD=		${LIBFETCH} ${LIBMD}
LDADD=		-lfetch -lmd
.endif
.ifdef WITH_SOAAP
CFLAGS+=  -I${SOAAP_SOURCE_DIR}/include
.endif

.include <bsd.prog.mk>
