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

#ifndef _FETCH_INTERNAL_H_
#define _FETCH_INTERNAL_H_

#include <stdio.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/limits.h>
#ifndef NO_SANDBOX
#include <common.h>
#endif
#include <fetch.h>
/* Maximum URL length handled */
#define URL_MAX	2048
#define MINBUFSIZE	4096
#define TIMEOUT		120
//#define PATH_MAX	2048

/* Option flags */
int	 A_flag;	/*    -A: do not follow 302 redirects */
int	 a_flag;	/*    -a: auto retry */
off_t	 B_size;	/*    -B: buffer size */
int	 b_flag;	/*!   -b: workaround TCP bug */
char    *c_dirname;	/*    -c: remote directory */
int	 d_flag;	/*    -d: direct connection */
int	 F_flag;	/*    -F: restart without checking mtime  */
char	*f_filename;	/*    -f: file to fetch */
char	*h_hostname;	/*    -h: host to fetch from */
int	 i_flag;	/*    -i: specify input file for mtime comparison */
char	*i_filename;	/*        name of input file */
int	 l_flag;	/*    -l: link rather than copy file: URLs */
int	 m_flag;	/* -[Mm]: mirror mode */
char	*N_filename;	/*    -N: netrc file name */
int	 n_flag;	/*    -n: do not preserve modification time */
int	 o_flag;	/*    -o: specify output file */
int	 o_directory;	/*        output file is a directory */
char	*o_filename;	/*        name of output file */
int	 o_stdout;	/*        output file is stdout */
int	 once_flag;	/*    -1: stop at first successful file */
int	 p_flag;	/* -[Pp]: use passive FTP */
int	 R_flag;	/*    -R: don't delete partially transferred files */
int	 r_flag;	/*    -r: restart previously interrupted transfer */
off_t	 S_size;        /*    -S: require size to match */
int	 s_flag;        /*    -s: show size, don't fetch */
long	 T_secs;	/*    -T: transfer timeout in seconds */
int	 t_flag;	/*!   -t: workaround TCP bug */
int	 U_flag;	/*    -U: do not use high ports */
int	 v_level;	/*    -v: verbosity level */
int	 v_tty;		/*        stdout is a tty */
pid_t	 pgrp;		/*        our process group */
long	 w_secs;	/*    -w: retry delay */
int	 family;	/* -[46]: address family to use */

int	 sigalrm;	/* SIGALRM received */
int	 siginfo;	/* SIGINFO received */
int	 sigint;	/* SIGINT received */

long	 ftp_timeout;		/* default timeout for FTP transfers */
long	 http_timeout;	/* default timeout for HTTP transfers */
char	*buf;		/* transfer buffer */


/* Sandbox return value */
int rv;

/* Prototypes */
#ifndef NO_SANDBOX
conn_t *fetch_connect_inparent(const char *, int, int, int);
void fetch_sandbox_init(void);
void fetch_sandbox_wait(void);
#endif
int fetch_wrapper(char *, const char *);
int fetch(char *, const char *);
struct url *fetchParseURL_wrapper(char *url);
FILE *fopen_wrapper(const char *path, const char *mode);
int stat_ims_wrapper(const char *path, struct stat *s);
int stat_restart_wrapper(const char *path, struct stat *s);
int stat_wrapper(const char *path, struct stat *s, uint32_t op);
int utimes_wrapper(const char *filename, const struct timeval times[2]);
int mkstemps_wrapper(char *template, int suffixlen);

#endif	/* _FETCH_INTERNAL_H_ */
