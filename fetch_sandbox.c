/*-
 * Copyright (c) 2013 Ilias Marinos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>

#ifndef NO_SANDBOX
#include <sandbox.h>
/*#include <sandbox_rpc.h>*/
#include <sys/capability.h>
#endif

#include <fetch.h>
#include "fetch_internal.h"

/* DPRINTF */
#ifdef DEBUG
#define DPRINTF(format, ...)				\
	fprintf(stderr, "%s [%d] " format "\n", 	\
	__FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#define MMIN(a, b) ((a) < (b) ? (a) : (b))

/* Operations */
#define NO_OP 0
#define PROXIED_FETCH 1
#define PROXIED_FETCH_PARSE_URL 2
#define HOST_REP_FETCHCONN 3
#define HOST_REP_OUTF 4

#define SANDBOX_REQ_FETCHCONN 101
#define SANDBOX_REQ_OUTF 102

#ifndef NO_SANDBOX
/* fetch sandbox control block */
struct sandbox_cb *fscb;

struct fetch_req {
	char	hf_req_url[URL_MAX];
	char	hf_req_path[URL_MAX];
	char	hf_req_i_filename[PATH_MAX];	/* name of input file */
	int	 v_level;	/*    -v: verbosity level */
	int	 family;	/* -[46]: address family to use */
	int	 d_flag;	/*    -d: direct connection */
	int	 A_flag;	/*    -A: do not follow 302 redirects */
	int	 i_flag;	/*    -i: specify input file for mtime comparison */
	int	 s_flag;        /*    -s: show size, don't fetch */
	int	 o_stdout;	/*        output file is stdout */
	int	 r_flag;	/*    -r: restart previously interrupted transfer */
	off_t	 S_size;        /*    -S: require size to match */
	int	 l_flag;	/*    -l: link rather than copy file: URLs */
	int	 F_flag;	/*    -F: restart without checking mtime  */
	int	 R_flag;	/*    -R: don't delete partially transferred files */
	int	 m_flag;	/* -[Mm]: mirror mode */
	off_t	 B_size;	/*    -B: buffer size */
	long	 ftp_timeout;		/* default timeout for FTP transfers */
	long	 http_timeout;	/* default timeout for HTTP transfers */
} __packed;

struct fetch_rep {
	off_t	hf_rep_retval;
} __packed;

struct fetch_parse_url_req {
	char url_s[URL_MAX];
} __packed;

struct fetch_parse_url_rep {
	char		 scheme[URL_SCHEMELEN+1];
	char		 user[URL_USERLEN+1];
	char		 pwd[URL_PWDLEN+1];
	char		 host[MAXHOSTNAMELEN+1];
	int		 port;
	off_t		 offset;
	size_t		 length;
	time_t		 ims_time;
	char doc[URL_MAX];
	int ret;
} __packed;

struct fetchconn_req {
  char    host[MAXHOSTNAMELEN+1];
  int     port;
  int     af;
  int     verbose;
} __packed;

struct fetchconn_rep {
  int ref;
} __packed;

struct outf_req {
	char fpath[256];
	char mode[8];
} __packed;

struct outf_rep {
	int ret;
} __packed;

static void fsandbox(void);
void
fetch_sandbox_init(void)
{

	fscb = calloc(1, sizeof(struct sandbox_cb));
	if(!fscb) {
		DPRINTF("[XXX] fscb wasn't initialized!");
		exit(-1);
	}
	sandbox_create(fscb, &fsandbox);

}

void
fetch_sandbox_wait(void)
{
	wait(&rv);
	DPRINTF("Sandbox's exit status is %d", WEXITSTATUS(rv));
}       

/* Called in parent to proxy the request though the sandbox */
static off_t
fetch_insandbox(char *origurl, const char *origpath)
{
	struct fetch_req req;
	struct fetch_rep rep;
	struct iovec iov_req, iov_rep;
	size_t len;
	uint32_t seqno, opno;
	u_char *buffer;

	/* Clear out req */
	bzero(&req, sizeof(req));

	/* Pass needed data */
	strlcpy(req.hf_req_url, origurl, sizeof(req.hf_req_url));
	strlcpy(req.hf_req_path, origpath, sizeof(req.hf_req_url));
	if (i_flag)
		strlcpy(req.hf_req_i_filename, i_filename,
			MMIN(sizeof(req.hf_req_i_filename), sizeof(i_filename)));
	req.v_level = v_level;
	req.d_flag = d_flag;
	req.A_flag = A_flag;
	req.i_flag = i_flag;
	req.s_flag = s_flag;
	req.o_stdout = o_stdout;
	req.r_flag = r_flag;
	req.S_size = S_size;
	req.l_flag = l_flag;
	req.F_flag = F_flag;
	req.R_flag = R_flag;
	req.m_flag = m_flag;
	req.B_size = B_size;
	req.http_timeout = http_timeout;
	req.ftp_timeout = ftp_timeout;


	iov_req.iov_base = &req;
	iov_req.iov_len = sizeof(req);

#if 0
	if (host_rpc(fscb, PROXIED_FETCH, &iov_req, 1,  &iov_rep, 1, &len) < 0)
		err(-1, "host_rpc");
	if (len != sizeof(rep))
		errx(-1, "host_rpc");
#endif

	if (host_sendrpc(fscb, PROXIED_FETCH, seqno, &iov_req, 1, NULL, 0) < 0)
		err(-1, "host_sendrpc");

	struct fetchconn *fconn;
	struct fetchconn_req fcreq;
	struct fetchconn_rep fcrep;
	struct outf_req ofreq;
	struct outf_rep ofrep;
	FILE *ofstream;
	int ofd;

	for (;;) {
		if (host_recvrpc(fscb, &opno, &seqno,  &buffer, &len) < 0) {
			if (errno == EPIPE) {
				DPRINTF("[XXX] EPIPE");
				exit(-1);
			} else {
				DPRINTF("[XXX] sandbox_recvrpc");
				err(-1, "sandbox_recvrpc");
			}
		}

		switch(opno) {
		case SANDBOX_REQ_FETCHCONN:
			DPRINTF("[HOST] SANDBOX_REQ_FETCHCONN");
			if(len != sizeof(struct fetchconn_req)) {
				DPRINTF("Ouch receive size mismatch!");
				exit(-1);
			}
			memmove(&fcreq, buffer, len);
			free(buffer);
			/* Let's get the actual conn */
			DPRINTF("Host: %s\nPort: %d", fcreq.host, fcreq.port);
			fconn = fetch_connect((const char *)fcreq.host, fcreq.port,
				fcreq.af, fcreq.verbose);

			/* Ops */
			if (!fconn) {
				DPRINTF("Failed to get fconn");
				errx(-1, "fetch_connect()");
			}

			/* Send back to the sandbox what is needed */
			fcrep.ref = fconn->ref;
			iov_req.iov_base = &fcrep;
			iov_req.iov_len = sizeof(fcrep);


			if (host_rpc_rights(fscb, HOST_REP_FETCHCONN, &iov_req, 1, &fconn->sd, 1,
				NULL, 0, NULL, NULL, NULL) < 0)
				err(-1, "host_rpc");
#if 0
			if (host_send_rights(fscb, (void *) &fcrep, sizeof(fcrep), 0,  &fconn->sd, 1) < 0)
				err(-1, "host_send_rights");

			if (host_recvrpc(fscb, &opno, &seqno,  &buffer, &len) < 0) {
				if (errno == EPIPE) {
					DPRINTF("[XXX] EPIPE");
					exit(-1);
				} else {
					DPRINTF("[XXX] sandbox_recvrpc");
					err(-1, "sandbox_recvrpc");
				}
			}

			DPRINTF("OK - B");
			if(len != sizeof(rep)) {
				DPRINTF("Ouch receive size mismatch!");
				exit(-1);
			}
			memmove(&rep, buffer, len);
			free(buffer);
#endif
			break;

		case SANDBOX_REQ_OUTF:
			DPRINTF("[HOST] SANDBOX_REQ_OUTF");
			if(len != sizeof(struct outf_req)) {
				DPRINTF("Ouch receive size mismatch!");
				exit(-1);
			}
			memmove(&ofreq, buffer, len);
			free(buffer);
			ofstream = fopen(ofreq.fpath, ofreq.mode);
			if(!ofstream) {
				ofrep.ret = -1;
				DPRINTF("We don't handle failure yet");
				exit(-1);
			}

			/* Send back to the sandbox what is needed */
			ofrep.ret = 0;
			iov_req.iov_base = &ofrep;
			iov_req.iov_len = sizeof(ofrep);

			ofd = fileno(ofstream);
			if (host_rpc_rights(fscb, HOST_REP_OUTF, &iov_req, 1,
				&ofd, 1, NULL, 0, NULL, NULL, NULL) < 0)
				err(-1, "host_rpc");
			DPRINTF("[HOST] Output file descriptor sent");
			if (host_recvrpc(fscb, &opno, &seqno,  &buffer, &len) < 0) {
				if (errno == EPIPE) {
					DPRINTF("[XXX] EPIPE");
					exit(-1);
				} else {
					DPRINTF("[XXX] sandbox_recvrpc");
					err(-1, "sandbox_recvrpc");
				}
			}
			if(len != sizeof(rep)) {
				DPRINTF("Ouch receive size mismatch!");
				exit(-1);
			}
			memmove(&rep, buffer, len);
			free(buffer);
			DPRINTF("[HOST] Got the final response");
			goto out;
		default:
			DPRINTF("WTF");
		}
	}

out:
	DPRINTF("Nice");
	return (rep.hf_rep_retval);
}

/* Called in sandbox and wraps the actual fetch */
static void
sandbox_fetch(struct sandbox_cb *scb, uint32_t opno, uint32_t seqno, char
	*buffer, size_t len)
{
	struct fetch_req req;
	struct fetch_rep rep;
	struct iovec iov;

	if (len != sizeof(req))
		err(-1, "sandbox_fetch: len %zu", len);

	/* Demangle data */
	bcopy(buffer, &req, sizeof(req));
	v_level = req.v_level;
	d_flag = req.d_flag;
	A_flag = req.A_flag;
	i_flag = req.i_flag;
	s_flag = req.s_flag;
	o_stdout = req.o_stdout;
	r_flag = req.r_flag;
	S_size = req.S_size;
	l_flag = req.l_flag;
	F_flag = req.F_flag;
	R_flag = req.R_flag;
	m_flag = req.m_flag;
	B_size = req.B_size;
	http_timeout = http_timeout;
	ftp_timeout = ftp_timeout;
	i_filename = (i_flag ? req.hf_req_i_filename: NULL);

	/* allocate buffer */
	if (B_size < MINBUFSIZE)
		B_size = MINBUFSIZE;
	if ((buf = malloc(B_size)) == NULL)
		errx(1, "%s", strerror(ENOMEM));

  DPRINTF("Calling fetch");
	rep.hf_rep_retval = fetch(req.hf_req_url, req.hf_req_path);
	bzero(&rep, sizeof(rep));
	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);
  DPRINTF("[SANDBOX] Sending retval");
	//if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
  if (sandbox_sendrpc(scb, HOST_REP_FETCHCONN, seqno, &iov, 1) < 0)
		err(-1, "sandbox_sendrpc");

}

/* called in sandboxed process */
conn_t *
fetch_connect_inparent(const char *host, int port, int af, int verbose)
{
  conn_t *conn;
  struct fetchconn_req fcreq;
  struct fetchconn_rep fcrep;
  uint32_t seqno = 0;
  struct iovec iov_req, iov_rep;
  int fdarray[1], fdcount; /* We expect a fd for SSL_INIT op */
  int *fdp;
  uint32_t opno;
  u_char *buffer;
  size_t len;

  bzero(&fcreq, sizeof(struct fetchconn_req));
  bzero(&fcrep, sizeof(struct fetchconn_rep));

  strlcpy(fcreq.host, host, MMIN(strlen(host) + 1, MAXHOSTNAMELEN));
  fcreq.port = port;
  fcreq.af = af;
  fcreq.verbose = verbose;

  /*bzero(&iov_req, sizeof(struct iovec));*/
  /*bzero(&iov_rep, sizeof(struct iovec));*/

  iov_req.iov_base = &fcreq;
  iov_req.iov_len = sizeof(fcreq);

  DPRINTF("[SANDBOX] Proxying fetch_connect call to parent");

  if (sandbox_sendrpc(fscb, SANDBOX_REQ_FETCHCONN, seqno, &iov_req, 1) < 0)
    err(-1, "sandbox_sendrpc");

  /* Get a ptr to fdarry and update the number of fds we are expecting */
  fdp = fdarray;
  fdcount = 1;
  if (sandbox_recvrpc_rights(fscb, &opno, &seqno, &buffer, &len, fdp, &fdcount)
       < 0) {
    if (errno == EPIPE)
      DPRINTF("[XXX] EPIPE");
    else
      DPRINTF("[XXX] sandbox_recvrpc_rights");
    exit(-1);
  }

  /* Demangle data */
  if (len != sizeof(struct fetchconn_rep)) {
    DPRINTF("Received len mismatch");
    exit(-1);
  }
  memmove(&fcrep, buffer, len);

  /*
   * Okay, if we are here we can allocate conn_t and update the socket fd and
   * refcount
   */
  if ((conn = calloc(1, sizeof(*conn))) == NULL)
    return NULL;

  conn->sd = dup(fdarray[0]);
  conn->ref = fcrep.ref;

  DPRINTF("[SANDBOX] OK, we have the conn");
  return conn;
}

static void
sandbox_fetchParseURL(struct sandbox_cb *scb, uint32_t opno, uint32_t seqno, char
	*buffer, size_t len)
{
	struct fetch_parse_url_req req;
	struct fetch_parse_url_rep rep;
	struct url *urlptr;
	struct iovec iov;

	/* Initialize data */
	bzero(&req, sizeof(req));
	bzero(&rep, sizeof(rep));
	bzero(&iov, sizeof(iov));

	/* Demangle data */
	bcopy(buffer, &req, sizeof(req));

	/* Perform the risky call */
  DPRINTF("Calling fetchParseURL");
	if ((urlptr = fetchParseURL(req.url_s)) == NULL) {
		warn("%s: parse error", req.url_s);
		rep.ret = -1; /* Indicate failure */
	}

	/* If it was a success */
	if (!rep.ret) {
		/*bcopy(urlptr, &rep.url_r, sizeof(struct url));*/
		strlcpy(rep.scheme, urlptr->scheme, sizeof(rep.scheme));
		strlcpy(rep.user, urlptr->user, sizeof(rep.user));
		strlcpy(rep.pwd, urlptr->pwd, sizeof(rep.pwd));
		strlcpy(rep.host, urlptr->host, sizeof(rep.host));
		rep.port = urlptr->port;
		rep.offset = urlptr->offset;
		rep.length = urlptr->length;
		rep.ims_time = urlptr->ims_time;
		strlcpy(rep.doc, urlptr->doc, sizeof(rep.doc));
	}

	iov.iov_base = &rep;
	iov.iov_len = sizeof(rep);

	/* Send the parsed URL back to the parent */
	if (sandbox_sendrpc(scb, opno, seqno, &iov, 1) < 0)
		err(-1, "sandbox_send_rpc");

	if (urlptr)
		fetchFreeURL(urlptr);
}


static void
fsandbox(void)
{
	uint32_t opno, seqno;
	u_char *buffer;
	size_t len;

  DPRINTF("Calling cap_enter()");
  cap_enter();  // begin sandboxed execution

	DPRINTF("===> In fetch_sandbox()");

	/* Get the output fd and URL from parent */
	if (sandbox_recvrpc(fscb, &opno, &seqno,  &buffer, &len) < 0) {
		if (errno == EPIPE) {
			DPRINTF("[XXX] EPIPE");
			exit(-1);
		}
		else {
			DPRINTF("[XXX] sandbox_recvrpc");
			err(-1, "sandbox_recvrpc");
		}
	}

  DPRINTF("Request received");

	switch(opno) {
#ifdef SANDBOX_FETCH
	case PROXIED_FETCH:
		/* fetch the url and return */
		sandbox_fetch(fscb, opno, seqno, (char *)buffer, len);
		break;
#endif
#ifdef SANDBOX_PARSE_URL
	case PROXIED_FETCH_PARSE_URL:
		sandbox_fetchParseURL(fscb, opno, seqno, (char *)buffer, len);
		break;
#endif    
	/* For future expansion */
	default:
		errx(-1, "sandbox_main: unknown op %d", opno);
	}

	/* Free buffer */
	free(buffer);

	DPRINTF("Sandbox exiting!");
	/* exit */
	exit(0);
}
#endif

int
fetch_wrapper(char *URL, const char *path)
{
	/* Currently haven't tested using both sandboxes at once */
#ifdef SANDBOX_FETCH  
	return (fetch_insandbox(URL, path));
#else
	return (fetch(URL, path));
#endif
}

struct url *
fetchParseURL_wrapper(char *URL)
{
	struct url *uptr;

#ifndef SANDBOX_PARSE_URL
  DPRINTF("Directly calling fetchParseURL");
	if ((uptr = fetchParseURL(URL)) == NULL) {
		warnx("%s: parse error", URL);
		return NULL;
	}
#else
  DPRINTF("Proxying to sandbox");
	size_t len;
	struct fetch_parse_url_req req;
	struct fetch_parse_url_rep rep;
	struct iovec iov_req, iov_rep;


	/* Init data */
	bzero(&rep, sizeof(rep));
	bzero(&iov_req, sizeof(iov_req));
	bzero(&iov_rep, sizeof(iov_rep));

	strlcpy(req.url_s, URL, sizeof(req.url_s));
	iov_req.iov_base = &req;
	iov_req.iov_len = sizeof(req);
	iov_rep.iov_base = &rep;
	iov_rep.iov_len = sizeof(rep);
	if (host_rpc(fscb, PROXIED_FETCH_PARSE_URL, &iov_req, 1,  &iov_rep, 1, &len)
		< 0)
		err(-1, "host_rpc");

	if (len != sizeof(rep))
		err(-1, "host_rpc");

	/*ret should be 0 for success */
	if (rep.ret)
		return NULL;


	DPRINTF("SCHEME: %s HOST: %s, PORT: %d DOC: %s", rep.scheme, rep.host,
		rep.port, rep.doc);
	uptr = fetchMakeURL(rep.scheme, rep.host, rep.port, rep.doc, rep.user, rep.pwd);
#endif

	DPRINTF("SCHEME: %s HOST: %s, PORT: %d DOC: %s USR: %s PWD: %s OFFSET: %ld",
		uptr->scheme, uptr->host, uptr->port, uptr->doc, uptr->user, uptr->pwd,
		uptr->offset);

	return uptr;
}

FILE *
fopen_wrapper(const char *path, const char *mode)
{
    DPRINTF("In fopen_wrapper");

#ifdef SANDBOX_FETCH
	struct outf_req ofreq;
	struct outf_rep ofrep;
	uint32_t seqno = 0;
	struct iovec iov_req, iov_rep;
	int fdarray[1], fdcount; /* We expect a fd for SSL_INIT op */
	int *fdp;
	uint32_t opno;
	u_char *buffer;
	size_t len;

	bzero(&ofreq, sizeof(struct outf_req));
	bzero(&ofrep, sizeof(struct outf_rep));

	strlcpy(ofreq.fpath, path, MMIN(strlen(path) + 1, 256));
	strlcpy(ofreq.mode, mode, MMIN(strlen(mode) + 1, 8));

	/*bzero(&iov_req, sizeof(struct iovec));*/
	/*bzero(&iov_rep, sizeof(struct iovec));*/

	iov_req.iov_base = &ofreq;
	iov_req.iov_len = sizeof(ofreq);

	if (sandbox_sendrpc(fscb, SANDBOX_REQ_OUTF, seqno, &iov_req, 1) < 0)
		err(-1, "sandbox_sendrpc");

	/* Get a ptr to fdarry and update the number of fds we are expecting */
	fdp = fdarray;
	fdcount = 1;
	if (sandbox_recvrpc_rights(fscb, &opno, &seqno, &buffer, &len, fdp, &fdcount)
		< 0) {
		if (errno == EPIPE)
			DPRINTF("[XXX] EPIPE");
		else
			DPRINTF("[XXX] sandbox_recvrpc_rights");
		exit(-1);
	}

	/* Demangle data */
	if (len != sizeof(struct outf_rep)) {
		DPRINTF("Received len mismatch");
		exit(-1);
	}
	memmove(&ofrep, buffer, len);
	free(buffer);

	if (ofrep.ret == -1) {
		return NULL;
	}

	DPRINTF("[SANDBOX] Got the file descriptor from parent");

	/* Okay lets get a stream out of the fd */
	return(fdopen(fdarray[0], mode));
#else
    return fopen(path, mode);
#endif

}
