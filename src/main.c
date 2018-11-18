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
#include <tls.h>

#define GOP_PORT 70
#define GOP_TLS_PORT 343
#define GOP_HOST "localhost"
#define CRLF "\n\r"

#define TLS_CA "/etc/ssl/cert.pem"
#define TLS_CERT "geomys.pem"
#define TLS_KEY "geomys.key"

struct tls_config *tlscfg;
struct tls *ctx;

static void 
sigchild_handler(int signum) 
{
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

int
main(int argc, char *argv[])
{
	int sd, gop_len;
	struct sockaddr_in server_sa, gop;
	struct sigaction sa;
	u_short port;

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
	if (listen(sd,3) == -1)
		err(1, "Cannot listen()");
	sa.sa_handler = sigchild_handler;
        sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		err(1, "sigaction failed");

	printf("Geomys listening on %s:%u\n", GOP_HOST, port);
	for(;;) {
		int gop_sd;
		gop_len = sizeof(&gop);
		if ((gop_sd = accept(sd, (struct sockaddr *)&gop, 
					&gop_len)) == -1)
			err(1, "Cannot accept connection");

		/* serve gopher */
	}
}
