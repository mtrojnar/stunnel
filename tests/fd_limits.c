/* Regression tests for fd.c's sysconf handling and descriptor limits. */
#include "prototypes.h"

#if defined(HAVE_SYSCONF) && !defined(USE_FORK)

#ifdef TEST_SELECT
#undef USE_POLL
#endif

static long query_result;
static int query_errno, query_calls, error_calls, observed_errno;
static int failures;
int max_clients;

static long test_sysconf(int name) {
    ++query_calls;
    if(name!=_SC_OPEN_MAX || errno!=0) {
        fprintf(stderr, "Unexpected sysconf argument=%d or initial errno=%d\n",
            name, errno);
        ++failures;
    }
    errno=query_errno;
    return query_result;
}

/* Compile the production implementation, not a copy of its algorithm. */
#define sysconf test_sysconf
#include "../src/fd.c"
#undef sysconf

void s_log(int level, const char *format, ...) {
    va_list ap;

    (void)level;
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
    putchar('\n');
}

void ioerror(const char *txt) {
    ++error_calls;
    observed_errno=errno;
    printf("ioerror(%s): errno=%d\n", txt, errno);
}

void sockerror(const char *txt) {
    fprintf(stderr, "Unexpected sockerror(%s)\n", txt);
    ++failures;
}

static void check(const char *name, long result, int err, int errors,
        long expected_fds, int expected_clients) {
    query_result=result;
    query_errno=err;
    query_calls=error_calls=observed_errno=0;
    errno=EIO; /* The caller must clear stale errno before querying. */
    printf("Case %s: sysconf=%ld errno=%d; expected errors=%d fds=%ld clients=%d\n",
        name, result, err, errors, expected_fds, expected_clients);
    get_limits();
    printf("Observed: calls=%d errors=%d error_errno=%d fds=%ld clients=%d\n",
        query_calls, error_calls, observed_errno, (long)max_fds, max_clients);
    if(query_calls!=1 || error_calls!=errors ||
            (errors && observed_errno!=err) ||
            (long)max_fds!=expected_fds || max_clients!=expected_clients) {
        fprintf(stderr, "FAILED case %s\n", name);
        ++failures;
    }
}

int main(void) {
    long unlimited_fds=0;
    int unlimited_clients=0;

#ifndef USE_POLL
    unlimited_fds=FD_SETSIZE;
    unlimited_clients=FD_SETSIZE>=256 ? FD_SETSIZE*125/256 : (FD_SETSIZE-6)/2;
#endif
    /* Small limits exercise both the minimum and the low-limit formula. */
    check("success", 32, 0, 0, 32, 13);
    check("success with nonzero errno", 32, EINVAL, 0, 32, 13);
    check("minimum", 8, 0, 0, 16, 5);
    check("indeterminate", -1, 0, 0, unlimited_fds, unlimited_clients);
    check("failed", -1, EINVAL, 1, unlimited_fds, unlimited_clients);
    check("zero limit", 0, 0, 0, unlimited_fds, unlimited_clients);
#ifdef USE_POLL
    check("large limit", 512, 0, 0, 512, 250);
#else
    check("select cap", 2L*FD_SETSIZE, 0, 0,
        unlimited_fds, unlimited_clients);
#endif
    printf("Descriptor-limit regression: %s\n", failures ? "FAILED" : "passed");
    return failures ? 1 : 0;
}

#else

int main(void) {
    puts("Descriptor-limit regression requires sysconf and non-fork threading");
    return 77;
}

#endif
