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
LIBFETCH_DIR?= ../libfetch_c
LIBSEP_DIR?= ../libsep
.ifdef WITH_SOAAP
CC=      ${LLVM_BUILD_DIR}/bin/clang
CFLAGS+=  -DWITH_SOAAP -I${SOAAP_SOURCE_DIR}/include -I${LIBFETCH_DIR} -I${LIBSEP_DIR}
.ifdef SANDBOX_FETCH
CFLAGS+=  -DSANDBOX_FETCH
.endif
.ifdef SANDBOX_PARSE_URL
CFLAGS+=  -DSANDBOX_PARSE_URL
.endif
.ifdef SANDBOX_EPHEMERAL
CFLAGS+=  -DSANDBOX_EPHEMERAL
.endif

${PROG}-libfetch.bc-a: ${PROG}.bc-a
	${LLVM_BUILD_DIR}/bin/llvm-link -o ${.TARGET} ${.ALLSRC} ${LIBFETCH_DIR}/libfetch.bc-a
.endif

.include <bsd.prog.mk>

soaap_fetch:
	make -DWITH_LLVM_INSTRUMENTED -DWITH_SOAAP -DSANDBOX_FETCH fetch-libfetch.soaap_perf
	mv fetch-libfetch.soaap_perf fetch

soaap_parse:
	make -DWITH_LLVM_INSTRUMENTED -DWITH_SOAAP -DSANDBOX_PARSE_URL fetch-libfetch.soaap_perf
	mv fetch-libfetch.soaap_perf fetch
