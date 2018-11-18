/*
 * Copyright (c) 2018 int16h <int16h@openbsd.space>
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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <tls.h>

#define GOP_USER "nobody" 
#define GOP_PORT 70
#define GOP_TLS_PORT 343
#define GOP_HOST "localhost"
#define CRLF "\n\r"

#define MAXREQ 100
#define BUFLEN 1024

#define TLS_CA "/etc/ssl/cert.pem"
#define TLS_CERT "geomys.pem"
#define TLS_KEY "geomys.key"

struct tls_config *tlscfg;
struct tls *ctx;
struct tls *cctx;

uid_t uid;
gid_t gid;

static void 
sigchild_handler(int signum) 
{
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

static int
drop_p()
{
	errno = 0;
	struct passwd *upasswd;
	if ((upasswd = getpwnam(GOP_USER)) == NULL)
		errx(1, "Couldn't find user %s", GOP_USER);
	if (setgid(upasswd->pw_gid) == -1)
		errx(1, "Couldn't set GID");
	if (setgroups(0, NULL) == -1)
		errx(1, "Could not remove other groups");
	if (setuid(upasswd->pw_uid) == -1)
		errx(1, "Could not set UID");
	if (getuid() == 0)
		errx(1, "GOP_USER cannot be root!");	

char *pledgefest = "stdio rpath wpath cpath \
tmppath inet dns fattr flock \
unix getpw sendfd recvfd tty error";

        if (unveil("/tmp", "rcw") == -1)
                err(1, "unveil");
        if (unveil("/etc/hosts", "r") == -1)
                err(1, "unveil");
        if (unveil("/etc/resolv.conf", "r") == -1)
                err(1, "unveil");
        if (pledge(pledgefest, NULL) == -1)
                 err(1, "pledge");

	return 0;
}

int 
crlf_foo( char * buf, size_t size ){
    char * pos = memchr(buf, '\n', size);
    if( pos != NULL ){
        *(pos-1) = 0;
        return 1;
    }
    return 0;
}

void
handle_req(struct tls *fd)
{
	ssize_t r = -1;
	ssize_t rc = 0;
	ssize_t maxread;
	char buf[128];
	maxread = sizeof(buf) - 1;
	while ((r != 0) && rc < maxread) {
		r = tls_read(fd, buf + rc, maxread - rc);
	        if(r <= 0){
            		buf[rc] = 0;
			break;
		}
/*		if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
 *			continue;
 */		if (r < 0)
			warnx("tls_read failed (%s)", 
				tls_error(cctx));
		rc += r;
		if (crlf_foo(buf, rc))
			break;
	}
	buf[rc] = '\0';
	printf("<< %s\n", buf);
}

int
main(int argc, char *argv[])
{
	int sd, gop_len, i;
	struct sockaddr_in server_sa, gop;
	struct sigaction sa;
	u_short port;
	char buffer[128];
	size_t maxread;
	
	if ((GOP_TLS_PORT < 1024) && (getuid() != 0))
		errx(1, "Privileged port %u requires a privileged user!", 
				GOP_TLS_PORT);
	sd = socket( PF_INET, SOCK_STREAM, 0 );
	if (tls_init() == -1)
		err(1, "tls_init() failed");
	tlscfg = tls_config_new();
	if (tls_config_set_ca_file(tlscfg, TLS_CA) == -1)
		err(1, "Cannot set CA file");
	if (tls_config_set_key_file(tlscfg, TLS_KEY) == -1)
		err(1, "Cannot set key");
	if (tls_config_set_cert_file(tlscfg, TLS_CERT) == -1)
		err(1, "Cannot set cert");
	if ((ctx = tls_server()) == NULL)
		err(1, "Cannot create TLS server");
	if (tls_configure(ctx, tlscfg) == -1)
		errx(1, "tls_configure failed (%s)", tls_error(ctx));
	port = GOP_TLS_PORT;

	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sd, (struct sockaddr *) &server_sa, 
			sizeof(server_sa)) == -1)
		err(1, "Cannot bind()");
	if (listen(sd, MAXREQ) == -1)
		err(1, "Cannot listen()");
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(int)) == -1)
		err(1, "Cannot setsockopt()");

	sa.sa_handler = sigchild_handler;
        sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		err(1, "sigaction failed");
	drop_p();

	printf("Geomys listening on %s:%u\n", GOP_HOST, port);

	for(;;) {
		int gop_sd, i;
		gop_len = sizeof(&gop);
		if ((gop_sd = accept(sd, 
			(struct sockaddr *)&gop, &gop_len)) == -1)
				 err(1, "Cannot accept connection");
		if (tls_accept_socket(ctx, &cctx, gop_sd) == -1)
			errx(1, "Cannot accept tls  (%s)", tls_error(ctx));
		do {
			if ((i = tls_handshake(cctx)) == -1)
				warnx("Cannot handshake (%s)", 
					tls_error(cctx));
		} while (i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

		struct tls *req_fd = malloc(sizeof(cctx));
		req_fd = cctx;
		printf("New connection: %s\n", inet_ntoa(gop.sin_addr));
		handle_req(req_fd);
		
		tls_close(cctx);
		close(gop_sd);
	}
}
