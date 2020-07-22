/*
 **********************************************************************
 * Copyright (C) Miroslav Lichvar  2020
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * 
 **********************************************************************
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define CRITICAL_BIT (1 << 15)
#define MAX_MESSAGE_LENGTH (1024*1024)

struct test {
	struct {
		int tls12;
		int unknown_alpn;
		int next_protocol;
		int next_protocols;
		int aead_algorithm;
		int aead_algorithms;
		int server_negotiation;
		int port_negotiation;
		int unknown_critical;
		int unknown_noncritical;
		int no_end;
		int min_request_length;
		int max_send_length;
	} in;
	struct {
		int connection;
		int handshake;
		int alpn;
		int sent;
		int all_sent;
		int received;
		int no_unknown_critical;
		int end;

		int next_protocol;
		int error;
		int aead_algorithm;
		int cookies;
	} out;
};

static int debug;

static gnutls_priority_t priority_cache_tls13;
static gnutls_priority_t priority_cache_tls12;
static gnutls_certificate_credentials_t credentials;

static char *server_name;
static struct sockaddr *server_addr;
static socklen_t server_addr_len;
static int min_delay = 0;
static int max_delay = 10000;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int quit_perf = 0;
static int any_failed_tests;

static int concurrent_sessions = 0;
static int max_concurrent_sessions = 0;
static int failed_sessions = 0;
static int successful_sessions = 0;


static void update_stat(int inc, int *val, int *max) {
	pthread_mutex_lock(&lock);
	*val += inc;
	if (*max < *val)
		*max = *val;
	pthread_mutex_unlock(&lock);
}

static gnutls_session_t create_session(struct test *test)
{
	gnutls_session_t session;
	gnutls_datum_t alpn, alpn2;
	struct timeval tv;
	int fd, r;

	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if ((fd = socket(server_addr->sa_family, SOCK_STREAM, 0)) < 0)
	       return NULL;

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0 ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) < 0 ||
	    connect(fd, server_addr, server_addr_len) < 0) {
		if (debug)
			fprintf(stderr, "Could not connect : %s\n", strerror(errno));
		close(fd);
		usleep(100000);
		return NULL;
	}

	test->out.connection = 1;

	if (gnutls_init(&session, GNUTLS_CLIENT | GNUTLS_NO_SIGNAL) < 0) {
		close(fd);
		return NULL;
	}

	gnutls_transport_set_int(session, fd);
#if 0
	if (server_name)
		gnutls_session_set_verify_cert(session, server_name, 0);
#endif

	if (test->in.unknown_alpn)
		alpn.data = (unsigned char *)"unknown";
	else
		alpn.data = (unsigned char *)"ntske/1";
	alpn.size = sizeof ("ntske/1") - 1;

	if ((server_name && gnutls_server_name_set(session, GNUTLS_NAME_DNS, server_name, strlen(server_name)) < 0) ||
	    gnutls_priority_set(session, test->in.tls12 ? priority_cache_tls12 : priority_cache_tls13) < 0 ||
	    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, credentials) < 0 ||
	    gnutls_alpn_set_protocols(session, &alpn, 1, 0) < 0) {
		fprintf(stderr, "Could not set up session\n");
		gnutls_deinit(session);
		close(fd);
		return NULL;
	}

	if ((r = gnutls_handshake(session)) < 0) {
		if (debug)
			fprintf(stderr, "TLS handshake failed : %s\n", gnutls_strerror(r));
		gnutls_deinit(session);
		close(fd);
		usleep(100000);
		return NULL;
	}

	test->out.handshake = 1;

	if (gnutls_alpn_get_selected_protocol(session, &alpn2) >= 0 &&
	    alpn2.size == alpn.size && memcmp(alpn.data, alpn2.data, alpn.size) == 0)
		test->out.alpn = 1;

	return session;
}

static int send_request(gnutls_session_t session, struct test *test) {
	int i, j, r, length, slength, sent, calls, fails;
	uint16_t *data;

	data = malloc(MAX_MESSAGE_LENGTH);
	if (!data)
		exit(4);

	i = 0;

	if (test->in.unknown_critical >= 0) {
		assert(test->in.unknown_critical % 2 == 0);
		data[i++] = htons(CRITICAL_BIT | 100);
		data[i++] = htons(test->in.unknown_critical);
		memset(&data[i], 0, test->in.unknown_critical);
		i += test->in.unknown_critical / 2;
	}

	if (test->in.unknown_noncritical >= 0) {
		assert(test->in.unknown_noncritical % 2 == 0);
		data[i++] = htons(100);
		data[i++] = htons(test->in.unknown_noncritical);
		memset(&data[i], 0, test->in.unknown_noncritical);
		i += test->in.unknown_noncritical / 2;
	}

	/* NEXT_PROTOCOL */
	if (test->in.next_protocol >= 0) {
		for (j = 0; j < test->in.next_protocols; j++) {
			data[i++] = htons(CRITICAL_BIT | 1);
			data[i++] = htons(2);
			data[i++] = htons(test->in.next_protocol);
		}
	}

	/* AEAD_ALGORITHM */
	if (test->in.aead_algorithm >= 0) {
		for (j = 0; j < test->in.aead_algorithms; j++) {
			data[i++] = htons(CRITICAL_BIT | 4);
			data[i++] = htons(2);
			data[i++] = htons(test->in.aead_algorithm);
		}
	}

	/* SERVER_NEGOTIATION */
	if (test->in.server_negotiation >= 0) {
		assert(test->in.server_negotiation % 2 == 0);
		data[i++] = htons(6);
		data[i++] = htons(test->in.server_negotiation);
		memset(&data[i], 'a', test->in.server_negotiation);
		i += test->in.server_negotiation / 2;
	}

	/* PORT_NEGOTIATION */
	if (test->in.port_negotiation >= 0) {
		data[i++] = htons(7);
		data[i++] = htons(2);
		data[i++] = htons(test->in.port_negotiation);
	}

	while (2 * i + 4 < test->in.min_request_length) {
		assert(test->in.min_request_length % 2 == 0);
		j = test->in.min_request_length - 2 * i - 4 - 4;
		data[i++] = htons(100);
		if (j < 0)
			j = 0;
		else if (j > 65534)
			j = 65534;
		data[i++] = htons(j);
		memset(&data[i], 0, j);
		i += j / 2;
	}

	/* END_OF_MESSAGE */
	if (!test->in.no_end) {
		data[i++] = htons(CRITICAL_BIT | 0);
		data[i++] = htons(0);
	}

	length = i * sizeof data[0];
	assert(length <= MAX_MESSAGE_LENGTH);

	for (sent = calls = fails = 0; sent < length; sent += r, calls++) {
		if (max_delay > 0 && min_delay <= max_delay)
			usleep(random() % (max_delay - min_delay + 1) + min_delay);

		slength = length - sent;
		if (slength > test->in.max_send_length)
			slength = test->in.max_send_length;

		r = gnutls_record_send(session, (unsigned char *)data + sent, slength);
		if (r < 0) {
			if (gnutls_error_is_fatal(r)) {
				if (debug)
					fprintf(stderr, "send failed : %s\n", gnutls_strerror(r));
				break;
			} else if (++fails >= 10) {
				if (debug)
					fprintf(stderr, "Session timed out\n");
				break;
			}
			r = 0;
		}
	}

	test->out.sent = sent;
	test->out.all_sent = sent == length;

	free(data);

	if (debug)
		fprintf(stderr, "Sent %d/%d bytes in %d calls\n", sent, length, calls);

	return test->out.all_sent;
}

static int get_record(unsigned char *data, int length, int *type, int *blength) {
	uint16_t x;

	if (length < 4)
		return 0;

	memcpy(&x, data, sizeof (x));
	*type = ntohs(x);
	memcpy(&x, data + 2, sizeof (x));
	*blength = ntohs(x);

	if (*blength > length - 4)
		return 0;

	return 1;
}

static int is_message_complete(unsigned char *data, int length) {
	int type, blength;

	for (; length > 0; length -= 4 + blength, data += 4 + blength) {
		if (!get_record(data, length, &type, &blength))
			return 0;
		if (length == 4 && blength == 0 && (type & ~CRITICAL_BIT) == 0)
			return 1;
	}

	return 0;
}

static int receive_response(gnutls_session_t session, struct test *test) {
	int r, received, calls, left, records, type, blength;
	unsigned char *data, *d;
	struct timeval start_tv, tv;

	data = malloc(MAX_MESSAGE_LENGTH);
	if (!data)
		exit(4);

	gettimeofday(&start_tv, NULL);

	for (received = calls = 0; received < MAX_MESSAGE_LENGTH; received += r, calls++) {
		r = gnutls_record_recv(session, data + received, MAX_MESSAGE_LENGTH - received);

		if (r < 0) {
		       	if (gnutls_error_is_fatal(r)) {
				if (debug)
					fprintf(stderr, "recv failed : %s\n", gnutls_strerror(r));
				break;
			}
			r = 0;
		} else if (r == 0) {
			break;
		}

		gettimeofday(&tv, NULL);
		if ((tv.tv_sec - start_tv.tv_sec) + (tv.tv_usec - start_tv.tv_usec) * 1e-6 > 1.0) {
			if (debug)
				fprintf(stderr, "Session timed out\n");
			break;
		}

		if (is_message_complete(data, received))
			break;
	}

	if (debug)
		fprintf(stderr, "Received %d bytes in %d calls\n", received, calls);

	test->out.received = received;
	test->out.no_unknown_critical = 1;

	for (records = 0, left = received; left > 0; records++, left -= 4 + blength) {
		d = data + received - left;
		if (!get_record(d, left, &type, &blength))
			break;
		switch (type & ~CRITICAL_BIT) {
			case 0: /* END_OF_MESSAGE */
				if (left == 4 && blength == 0 && type & CRITICAL_BIT)
					test->out.end = 1;
				break;
			case 1: /* NEXT_PROTOCOL */
				if (type & CRITICAL_BIT && blength == 2)
					test->out.next_protocol = (d[4] << 8) | d[5];
				break;
			case 2: /* ERROR */
				if (type & CRITICAL_BIT && blength == 2)
					test->out.error = (d[4] << 8) | d[5];
				break;
			case 3: /* WARNING */
				break;
			case 4: /* AEAD_ALGORITHM */
				if (blength == 2)
					test->out.aead_algorithm = (d[4] << 8) | d[5];
				break;
			case 5: /* COOKIE */
				test->out.cookies++;
				break;
			case 6: /* SERVER_NEGOTIATION */
				break;
			case 7: /* PORT_NEGOTIATION */
				break;
			default:
				if (type & CRITICAL_BIT)
					test->out.no_unknown_critical = 0;
				break;
		}
	}

	if (debug)
		fprintf(stderr, "Parsed %d records in %d/%d bytes\n", records, received - left, received);

	free(data);

	return test->out.end;
}

static void destroy_session(gnutls_session_t session) {
	int fd = gnutls_transport_get_int(session);
	struct linger linger;

	/* Quickly free the local port */
	linger.l_onoff = 1;
	linger.l_linger = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof linger) < 0)
	    ;

	close(fd);
	gnutls_deinit(session);
}

static int run_ntske_session(struct test *test) {
	gnutls_session_t session;

	session = create_session(test);
	if (!session)
		goto error;

	update_stat(1, &concurrent_sessions, &max_concurrent_sessions);

	if (!send_request(session, test)) {
		update_stat(-1, &concurrent_sessions, &max_concurrent_sessions);
		goto error;
	}

	update_stat(-1, &concurrent_sessions, &max_concurrent_sessions);

	if (!receive_response(session, test))
		goto error;

	if (gnutls_bye(session, GNUTLS_SHUT_RDWR) < 0)
		goto error;

	destroy_session(session);

	update_stat(1, &successful_sessions, &successful_sessions);
	return 1;
error:
	if (session)
		destroy_session(session);
	update_stat(1, &failed_sessions, &failed_sessions);
	return 0;
}

static void reset_test(struct test *test) {
	memset(test, 0, sizeof *test);

	test->in.next_protocol = 0;
	test->in.next_protocols = 1;
	test->in.aead_algorithm = 15;
	test->in.aead_algorithms = 1;
	test->in.server_negotiation = -1;
	test->in.port_negotiation = -1;
	test->in.unknown_critical = -1;
	test->in.unknown_noncritical = -1;
	test->in.max_send_length = MAX_MESSAGE_LENGTH;

	test->out.next_protocol = -1;
	test->out.error = -1;
	test->out.aead_algorithm = -1;
}

static void run_test(struct test *test, const char *desc) {
	int i, r;
	char buf[32];

	printf("%s", desc);
	for (i = 40 - (int)strlen(desc); i > 0; i--)
		printf(" ");

	r = run_ntske_session(test);

	snprintf(buf, sizeof buf, "(%d+%d)", test->out.sent, test->out.received);
	printf("%-16s", buf);

	if (debug) {
		if (r)
			fprintf(stderr, "Session finished succesfully\n");
		else
			fprintf(stderr, "Session failed\n");
	}

	if (debug)
		fprintf(stderr, "Result: connection=%d handshake=%d no_unknown_critical=%d end=%d next_protocol=%d error=%d aead_algorithm=%d cookies=%d\n",
			test->out.connection, test->out.handshake, test->out.no_unknown_critical,
			test->out.end, test->out.next_protocol, test->out.error,
			test->out.aead_algorithm, test->out.cookies);
}

static int is_test_sane(struct test *test) {
	return test->out.connection && test->out.handshake && test->out.alpn &&
		test->out.all_sent && test->out.no_unknown_critical && test->out.end;
}

static int is_test_ok(struct test *test) {
	return is_test_sane(test) &&
		test->out.next_protocol == 0 && test->out.error == -1 &&
		test->out.aead_algorithm == 15 && test->out.cookies > 0;
}

static void set_result(int pass) {
	printf("%s\n", pass ? "PASS" : "FAIL");
	if (!pass)
		any_failed_tests = 1;
}

static void run_conf_tests(void) {
	struct test test;

	reset_test(&test);
	run_test(&test, "TLSv1.3 connection");
	set_result(test.out.connection && test.out.handshake);

	reset_test(&test);
	test.in.tls12 = 1;
	run_test(&test, "Rejection of TLSv1.2 connection");
	set_result(test.out.connection && !test.out.handshake);

	reset_test(&test);
	run_test(&test, "ALPN \"ntske/1\"");
	set_result(test.out.connection && test.out.alpn);

	reset_test(&test);
	test.in.unknown_alpn = 1;
	run_test(&test, "Rejection of unknown ALPN");
	set_result(test.out.handshake && !test.out.alpn && !test.out.end);

	reset_test(&test);
	run_test(&test, "Minimal valid request");
	set_result(is_test_ok(&test));

	reset_test(&test);
	run_test(&test, "Number of cookies");
	set_result(is_test_ok(&test) && test.out.cookies == 8);

	reset_test(&test);
	test.in.next_protocol = -1;
	run_test(&test, "Missing NEXT_PROTOCOL");
	set_result(is_test_sane(&test) && test.out.error == 1);

	reset_test(&test);
	test.in.next_protocol = 100;
	run_test(&test, "Unknown NEXT_PROTOCOL");
	set_result(is_test_sane(&test) && test.out.error == 1);

	reset_test(&test);
	test.in.next_protocols = 10;
	run_test(&test, "Multi-value NEXT_PROTOCOL");
	set_result(is_test_ok(&test));

	reset_test(&test);
	test.in.aead_algorithm = -1;
	run_test(&test, "Missing AEAD_ALGORITHM");
	set_result(is_test_sane(&test) && test.out.error == 1);

	reset_test(&test);
	test.in.aead_algorithm = 100;
	run_test(&test, "Unknown AEAD_ALGORITHM");
	set_result(is_test_sane(&test) && test.out.error == 1);

	reset_test(&test);
	test.in.aead_algorithms = 10;
	run_test(&test, "Multi-value AEAD_ALGORITHM");
	set_result(is_test_ok(&test));

	reset_test(&test);
	test.in.server_negotiation = 10;
	run_test(&test, "Unknown SERVER_NEGOTIATION");
	set_result(is_test_ok(&test));

	reset_test(&test);
	test.in.port_negotiation = 9999;
	run_test(&test, "Unknown PORT_NEGOTIATION");
	set_result(is_test_ok(&test));

	reset_test(&test);
	test.in.unknown_critical = 10;
	run_test(&test, "Unknown critical record");
	set_result(is_test_sane(&test) && test.out.error == 0);

	reset_test(&test);
	test.in.unknown_noncritical = 10;
	run_test(&test, "Unknown non-critical record");
	set_result(is_test_ok(&test));

	reset_test(&test);
	test.in.no_end = 1;
	run_test(&test, "Missing ENF_OF_MESSAGE");
	set_result(test.out.connection && test.out.handshake && !test.out.end);

	reset_test(&test);
	test.in.max_send_length = 1;
	test.in.unknown_noncritical = 32;
	run_test(&test, "Slow request");
	set_result(is_test_ok(&test));

	reset_test(&test);
	test.in.min_request_length = 1024;
	run_test(&test, "Long request");
	set_result(is_test_ok(&test));

	reset_test(&test);
	test.in.max_send_length = 479;
	test.in.min_request_length = MAX_MESSAGE_LENGTH;
	run_test(&test, "Very long request (not required)");
	printf("-\n");
}

static void *run_perf_session(void *x) {
	struct test test;

	reset_test(&test);

	while (!quit_perf) {
		if (!run_ntske_session(&test))
			continue;
	}

	return NULL;
}

static void handle_sigint(int x) {
	quit_perf = 1;
}

static void run_perf_test(int threads) {
	pthread_t pthreads[threads];
	struct test test;
	struct sigaction sa;
	int i;

	reset_test(&test);
	if (!run_ntske_session(&test)) {
		fprintf(stderr, "Could not make a single NTS-KE session\n");
		return;
	}

	sa.sa_handler = handle_sigint;
	sa.sa_flags = SA_RESTART;
	if (sigemptyset(&sa.sa_mask) < 0 ||
	    sigaction(SIGINT, &sa, NULL) < 0) {
		fprintf(stderr, "Could not set signal handler\n");
		exit(4);
	}

	for (i = 0; i < threads; i++) {
		if (pthread_create(&pthreads[i], NULL, run_perf_session, NULL) < 0) {
			fprintf(stderr, "Could not create thread\n");
			exit(4);
		}
	}

	while (!quit_perf) {
		usleep(1000000);

		pthread_mutex_lock(&lock);

		printf("%d successful sessions/sec, %d failed sessions, max %d concurrent sessions\n",
		       successful_sessions, failed_sessions, max_concurrent_sessions);
		successful_sessions = failed_sessions = max_concurrent_sessions = 0;

		pthread_mutex_unlock(&lock);
	}

	for (i = 0; i < threads; i++) {
		if (pthread_join(pthreads[i], NULL) < 0) {
			fprintf(stderr, "Could not join thread\n");
			exit(4);
		}
	}
}

static void print_help(void) {
	printf("ntske-test MODE [OPTION]... HOST\n");
	printf("\nModes:\n");
	printf("\t-c\t\tTest conformance\n");
	printf("\t-b\t\tTest performance\n");
	printf("\nOptions:\n");
	printf("\t-p PORT\t\tSet server NTS-KE port (4460)\n");
	printf("\t-t THREADS\tSet number of threads for performance tests (8)\n");
	printf("\t-m MILLISECONDS\tSet minimum random delay inserted between I/O (0)\n");
	printf("\t-M MILLISECONDS\tSet maximum random delay inserted between I/O (10)\n");
	printf("\t-d\t\tPrint debug messages\n");
	printf("\t-h\t\tPrint this help message\n");
}

int main(int argc, char **argv) {
	int threads = 8, conf_test = 0, perf_test = 0;
	const char *port = "4460";
	struct addrinfo *addrinfo;
       	char buf[128];
	int opt;

	setvbuf(stdout, NULL, _IONBF, 0);

	while ((opt = getopt(argc, argv, "bcdhm:M:p:r:t:")) != -1) {
		switch (opt) {
			case 'c':
				conf_test = 1;
				break;
			case 'b':
				perf_test = 1;
				break;
			case 'd':
				debug = 1;
				break;
			case 'm':
				min_delay = 1000 * atoi(optarg);
				if (max_delay < min_delay)
					max_delay = min_delay;
				break;
			case 'M':
				max_delay = 1000 * atoi(optarg);
				break;
			case 'p':
				port = optarg;
				break;
			case 't':
				threads = atoi(optarg);
				break;
			case 'h':
			default:
				print_help();
				exit(1);
		}
	}

	if (!(perf_test || conf_test) || optind >= argc) {
		print_help();
		exit(1);
	}

	server_name = argv[optind];

	if (getaddrinfo(server_name, port, NULL, &addrinfo) != 0) {
		fprintf(stderr, "Could not get address of %s\n", server_name);
		exit(2);
	}

	server_addr_len = addrinfo->ai_addrlen;
	server_addr = malloc(server_addr_len);
	memcpy(server_addr, addrinfo->ai_addr, server_addr_len);
	freeaddrinfo(addrinfo);

	/* Check if the name is just an address */
	if (inet_pton(AF_INET, server_name, buf) > 0 ||
	    inet_pton(AF_INET6, server_name, buf) > 0)
		server_name = NULL;

	switch (server_addr->sa_family) {
		case AF_INET:
			if (inet_ntop(server_addr->sa_family,
				      &((struct sockaddr_in *)server_addr)->sin_addr, buf, sizeof buf) < 0)
				exit(2);
			break;
		case AF_INET6:
			if (inet_ntop(server_addr->sa_family,
				      &((struct sockaddr_in6 *)server_addr)->sin6_addr, buf, sizeof buf) < 0)
				exit(2);
			break;
		default:
			exit(2);
	}

	fprintf(stderr, "Testing server %s (%s:%s)\n\n", server_name ? server_name : "?", buf, port);

	if (gnutls_priority_init2(&priority_cache_tls13,
				"-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.2",
				NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND) < 0 ||
	    gnutls_priority_init2(&priority_cache_tls12,
				"-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-TLS1.3",
				NULL, GNUTLS_PRIORITY_INIT_DEF_APPEND) < 0 ||
	    gnutls_certificate_allocate_credentials(&credentials) < 0 ||
	    gnutls_certificate_set_x509_system_trust(credentials) < 0) {
		fprintf(stderr, "Could not get/set priority cache or credentials\n");
		exit(3);
	}

	any_failed_tests = 0;

	if (conf_test)
		run_conf_tests();

	if (perf_test)
		run_perf_test(threads);

	gnutls_priority_deinit(priority_cache_tls13);
	gnutls_priority_deinit(priority_cache_tls12);
	free(server_addr);

	return any_failed_tests;
}
