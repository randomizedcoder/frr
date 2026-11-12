// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Table-driven tests for rpki_create_socket(), the rtrlib socket callback in
 * bgp_rpki.c. The file is included so the static function can be called, and
 * its VRF, privilege, resolver and socket calls are replaced by the stubs
 * below, so no thread, DNS or network access is needed.
 */
#include <zebra.h>
#include <limits.h>

#include "vrf.h"
#include "privs.h"
#include "frr_pthread.h"

static struct vrf *test_vrf_lookup_by_id(vrf_id_t id);
static struct vrf *test_vrf_lookup_by_name(const char *name);
static int test_frr_pthread_non_controlled_startup(pthread_t thread, const char *name,
						   const char *os_name);
static struct zebra_privs_t *test_zprivs_raise(struct zebra_privs_t *privs, const char *funcname);
static void test_zprivs_lower(struct zebra_privs_t **privs);
static int test_vrf_getaddrinfo(const char *host, const char *port, const struct addrinfo *hints,
				struct addrinfo **res, vrf_id_t id);
static int test_vrf_socket(int domain, int type, int protocol, vrf_id_t id, const char *name);
static void test_freeaddrinfo(struct addrinfo *res);
static int test_connect(int fd, const struct sockaddr *addr, socklen_t len);
static int test_close(int fd);
static int test_getsockopt(int fd, int level, int option, void *value, socklen_t *len);
static int test_setsockopt(int fd, int level, int option, const void *value, socklen_t len);

/* Substitute dependencies only in this translation unit. */
#define vrf_lookup_by_id		   test_vrf_lookup_by_id
#define vrf_lookup_by_name		   test_vrf_lookup_by_name
#define frr_pthread_non_controlled_startup test_frr_pthread_non_controlled_startup
#define _zprivs_raise			   test_zprivs_raise
#define _zprivs_lower			   test_zprivs_lower
#define vrf_getaddrinfo			   test_vrf_getaddrinfo
#define vrf_socket			   test_vrf_socket
#define freeaddrinfo			   test_freeaddrinfo
#define connect				   test_connect
#define close				   test_close
#define getsockopt			   test_getsockopt
#define setsockopt			   test_setsockopt
#include "bgpd/bgp_rpki.c"
#undef vrf_lookup_by_id
#undef vrf_lookup_by_name
#undef frr_pthread_non_controlled_startup
#undef _zprivs_raise
#undef _zprivs_lower
#undef vrf_getaddrinfo
#undef vrf_socket
#undef freeaddrinfo
#undef connect
#undef close
#undef getsockopt
#undef setsockopt

struct zebra_privs_t bgpd_privs;
struct event_loop *master;

/*
 * Normally defined by bgp_main.c, which also has the daemon's main().
 * bgp_rpki.c only registers on these hooks, so the hook objects are enough.
 */
struct hook _hook_bgp_hook_config_write_vrf = { .name = "bgp_hook_config_write_vrf" };
struct hook _hook_bgp_hook_vrf_update = { .name = "bgp_hook_vrf_update" };

enum failure {
	NO_FAILURE,
	THREAD_FAILURE,
	NO_VRF,
	INACTIVE_VRF,
	UNKNOWN_VRF,
	RESOLVE_FAILURE,
	SOCKET_FAILURE,
	CONNECT_FAILURE,
};

enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

struct socket_case {
	enum kind kind;
	const char *description;
	/* only meaningful in a build without SSH support */
	bool no_ssh_only;
	int type;
	const char *host;
	const char *port;
	int family;
	bool registered_thread;
	const char *vrfname;
	enum failure failure;
	bool null_cache;
	int socket_fd;
	int expected_result;
	unsigned int expected_resolves;
	unsigned int expected_frees;
	unsigned int expected_closes;
};

/* Results are callback results, not whether the test itself should pass. */
static const struct socket_case cases[] = {
	{
		.kind = POSITIVE,
		.description = "IPv4 TCP",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = POSITIVE,
		.description = "IPv6 TCP",
		.family = AF_INET6,
		.type = TCP,
		.host = "2001:db8::1",
		.port = "323",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = POSITIVE,
		.description = "hostname and service",
		.type = TCP,
		.host = "cache.example",
		.port = "rtr",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = POSITIVE,
		.description = "named VRF",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.vrfname = "blue",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "null cache",
		.type = TCP,
		.null_cache = true,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "thread registration fails",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.failure = THREAD_FAILURE,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "missing default VRF",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.failure = NO_VRF,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "missing named VRF",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.vrfname = "blue",
		.failure = NO_VRF,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "inactive VRF",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.failure = INACTIVE_VRF,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "unknown VRF ID",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.failure = UNKNOWN_VRF,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "resolver failure",
		.type = TCP,
		.host = "invalid.example",
		.port = "323",
		.failure = RESOLVE_FAILURE,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 1,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "socket creation failure",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.failure = SOCKET_FAILURE,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = NEGATIVE,
		.description = "connection failure closes socket",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.failure = CONNECT_FAILURE,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 1,
	},
	/* Config cannot create these types; inject them to exercise the guard. */
	{
		.kind = NEGATIVE,
		.description = "SSH type without SSH support",
		.no_ssh_only = true,
		.type = 1,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = BOUNDARY,
		.description = "port zero is passed to resolver",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "0",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = BOUNDARY,
		.description = "minimum nonzero port",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "1",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = BOUNDARY,
		.description = "maximum port",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "65535",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = BOUNDARY,
		.description = "file descriptor zero is success",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.socket_fd = 0,
		.expected_result = 0,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = BOUNDARY,
		.description = "negative cache type",
		.no_ssh_only = true,
		.type = -1,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = BOUNDARY,
		.description = "maximum signed cache type",
		.no_ssh_only = true,
		.type = INT_MAX,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = BOUNDARY,
		.description = "minimum signed cache type",
		.no_ssh_only = true,
		.type = INT_MIN,
		.socket_fd = 42,
		.expected_result = -1,
		.expected_resolves = 0,
		.expected_frees = 0,
		.expected_closes = 0,
	},
	{
		.kind = CORNER,
		.description = "full IPv6 address",
		.family = AF_INET6,
		.type = TCP,
		.host = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		.port = "65535",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = CORNER,
		.description = "IPv4 mapped IPv6",
		.family = AF_INET6,
		.type = TCP,
		.host = "::ffff:192.0.2.1",
		.port = "323",
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
	{
		.kind = CORNER,
		.description = "thread already registered",
		.type = TCP,
		.host = "192.0.2.1",
		.port = "323",
		.registered_thread = true,
		.socket_fd = 42,
		.expected_result = 42,
		.expected_resolves = 1,
		.expected_frees = 1,
		.expected_closes = 0,
	},
};

static const struct socket_case *current;
static struct vrf test_vrf;
static struct sockaddr_in address;
static struct sockaddr_in6 address6;
static struct addrinfo answer;
static unsigned int resolves, frees, closes, sockets, connects;
static unsigned int errors, startups;

#define CHECK(condition)                                                                          \
	do {                                                                                      \
		if (!(condition)) {                                                               \
			fprintf(stderr, "%s: %s\n", current->description, #condition);            \
			errors++;                                                                 \
		}                                                                                 \
	} while (0)

static struct vrf *test_vrf_lookup_by_id(vrf_id_t id)
{
	CHECK(id == VRF_DEFAULT);
	CHECK(current->vrfname == NULL);
	return current->failure == NO_VRF ? NULL : &test_vrf;
}

static struct vrf *test_vrf_lookup_by_name(const char *name)
{
	CHECK(current->vrfname && !strcmp(name, current->vrfname));
	return current->failure == NO_VRF ? NULL : &test_vrf;
}

static int test_frr_pthread_non_controlled_startup(pthread_t thread, const char *name,
						   const char *os_name)
{
	startups++;
	return current->failure == THREAD_FAILURE ? -1 : 0;
}

static struct zebra_privs_t *test_zprivs_raise(struct zebra_privs_t *privs, const char *funcname)
{
	CHECK(privs == &bgpd_privs);
	return NULL;
}

static void test_zprivs_lower(struct zebra_privs_t **privs)
{
}

static int test_vrf_getaddrinfo(const char *host, const char *port, const struct addrinfo *hints,
				struct addrinfo **res, vrf_id_t id)
{
	resolves++;
	/* On the unfixed code, reject unexpected calls without using host/port. */
	if (!current->expected_resolves)
		return EAI_FAIL;
	CHECK(host == current->host);
	CHECK(port == current->port);
	CHECK(hints->ai_family == AF_UNSPEC);
	CHECK(hints->ai_socktype == SOCK_STREAM);
	CHECK(hints->ai_flags == AI_ADDRCONFIG);
	CHECK(hints->ai_protocol == 0);
	CHECK(id == test_vrf.vrf_id);
	if (current->failure == RESOLVE_FAILURE)
		return EAI_NONAME;
	*res = &answer;
	return 0;
}

static int test_vrf_socket(int domain, int type, int protocol, vrf_id_t id, const char *name)
{
	sockets++;
	CHECK(domain == answer.ai_family);
	CHECK(type == answer.ai_socktype);
	CHECK(protocol == answer.ai_protocol);
	CHECK(id == test_vrf.vrf_id);
	CHECK(name == NULL);
	return current->failure == SOCKET_FAILURE ? -1 : current->socket_fd;
}

static void test_freeaddrinfo(struct addrinfo *res)
{
	CHECK(res == &answer);
	frees++;
}

static int test_connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	connects++;
	CHECK(fd == current->socket_fd);
	CHECK(addr == answer.ai_addr);
	CHECK(len == answer.ai_addrlen);
	return current->failure == CONNECT_FAILURE ? -1 : 0;
}

static int test_close(int fd)
{
	CHECK(fd == current->socket_fd);
	closes++;
	return 0;
}

static int test_getsockopt(int fd, int level, int option, void *value, socklen_t *len)
{
	CHECK(fd == current->socket_fd);
	CHECK(level == SOL_SOCKET);
	CHECK(option == SO_RCVTIMEO || option == SO_SNDTIMEO);
	CHECK(*len == sizeof(struct timeval));
	memset(value, 0, *len);
	return 0;
}

static int test_setsockopt(int fd, int level, int option, const void *value, socklen_t len)
{
	CHECK(fd == current->socket_fd);
	CHECK(level == SOL_SOCKET);
	CHECK(option == SO_RCVTIMEO || option == SO_SNDTIMEO);
	CHECK(len == sizeof(struct timeval));
	return 0;
}

static void run_case(struct cache *cache, struct rpki_vrf *rpki_vrf)
{
	struct rtr_tr_tcp_config tcp_config = {
		.host = (char *)current->host,
		.port = (char *)current->port,
	};
	int initial_state, final_state, result;

	resolves = frees = closes = sockets = connects = errors = startups = 0;
	cache->type = current->type;
	/* Invalid cache types have no transport config to dereference. */
	cache->tr_config.tcp_config = current->type == TCP ? &tcp_config : NULL;
	rpki_vrf->vrfname = (char *)current->vrfname;
	test_vrf.vrf_id = current->vrfname ? 77 : VRF_DEFAULT;
	test_vrf.status = VRF_ACTIVE;
	if (current->failure == UNKNOWN_VRF)
		test_vrf.vrf_id = VRF_UNKNOWN;
	if (current->failure == INACTIVE_VRF)
		test_vrf.status = 0;
	answer.ai_family = current->family ? current->family : AF_INET;
	answer.ai_addr = current->family == AF_INET6 ? (struct sockaddr *)&address6
						     : (struct sockaddr *)&address;
	answer.ai_addrlen = current->family == AF_INET6 ? sizeof(address6) : sizeof(address);

	CHECK(pthread_setspecific(rpki_pthread,
				  current->registered_thread ? &rpki_pthread : NULL) == 0);
	CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &initial_state) == 0);

	result = rpki_create_socket(current->null_cache ? NULL : cache);

	CHECK(pthread_setcancelstate(initial_state, &final_state) == 0);
	CHECK(final_state == PTHREAD_CANCEL_DISABLE);
	CHECK(startups == (!current->null_cache && !current->registered_thread ? 1U : 0U));
	CHECK(result == current->expected_result);
	CHECK(resolves == current->expected_resolves);
	CHECK(frees == current->expected_frees);
	CHECK(closes == current->expected_closes);
	CHECK(sockets == (current->expected_frees ? 1U : 0U));
	CHECK(connects ==
	      (current->expected_frees && current->failure != SOCKET_FAILURE ? 1U : 0U));
	if (errors)
		printf("    got result=%d resolve=%u free=%u close=%u\n", result, resolves, frees,
		       closes);
}

int main(void)
{
	struct rpki_vrf rpki_vrf = {};
	struct rtr_socket rtr_socket = {};
	struct cache cache = {};
	unsigned int failed = 0;

	if (pthread_key_create(&rpki_pthread, NULL) != 0) {
		fprintf(stderr, "pthread_key_create failed\n");
		return 1;
	}
	rtr_socket.thread_id = pthread_self();
	cache.rpki_vrf = &rpki_vrf;
	cache.rtr_socket = &rtr_socket;
	address.sin_family = AF_INET;
	address6.sin6_family = AF_INET6;
	answer.ai_socktype = SOCK_STREAM;
	answer.ai_protocol = IPPROTO_TCP;

	printf("RPKI cache socket tests\n\n");
	for (size_t i = 0; i < array_size(cases); i++) {
		current = &cases[i];
#ifdef FOUND_SSH
		/* type 1 is a real SSH cache here, so these cases don't apply */
		if (current->no_ssh_only) {
			printf("[%-8s] %s ... OK (skipped: built with SSH support)\n",
			       kind2str[current->kind], current->description);
			continue;
		}
#endif
		run_case(&cache, &rpki_vrf);
		printf("[%-8s] %s ... %s\n", kind2str[current->kind], current->description,
		       errors ? "failed" : "OK");
		failed += errors != 0;
	}
	pthread_setspecific(rpki_pthread, NULL);
	pthread_key_delete(rpki_pthread);
	printf("\n%u of %zu cases failed\n", failed, array_size(cases));
	return failed ? 1 : 0;
}
