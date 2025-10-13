/*
 * QGP Random Number Generation
 *
 * Implementation of cryptographically secure random number generation.
 */

#include "qgp_random.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

// Try getrandom() syscall first (Linux 3.17+)
#ifdef __linux__
#include <sys/random.h>
#endif

/**
 * Generate cryptographically secure random bytes
 *
 * Strategy:
 * 1. Try getrandom() syscall (Linux 3.17+, blocks if not initialized)
 * 2. Fallback to /dev/urandom (always available on Unix)
 *
 * Security note: getrandom() is preferred as it blocks until the system
 * entropy pool is initialized, preventing weak randomness at boot time.
 */
int qgp_randombytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) {
        return -1;
    }

#ifdef __linux__
    // Try getrandom() syscall first
    // Flag 0 = block until entropy pool initialized (secure)
    ssize_t ret = getrandom(buf, len, 0);
    if (ret >= 0 && (size_t)ret == len) {
        return 0;  // Success
    }

    // getrandom() failed or not available, fall through to /dev/urandom
    if (ret < 0 && errno != ENOSYS) {
        // Real error (not "syscall not available")
        fprintf(stderr, "getrandom() failed: %s\n", strerror(errno));
    }
#endif

    // Fallback: /dev/urandom
    // Note: /dev/urandom never blocks, even if entropy pool not initialized
    // This is acceptable fallback since getrandom() will be used on modern systems
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open /dev/urandom: %s\n", strerror(errno));
        return -1;
    }

    size_t bytes_read = fread(buf, 1, len, fp);
    fclose(fp);

    if (bytes_read != len) {
        fprintf(stderr, "Failed to read enough random bytes from /dev/urandom\n");
        return -1;
    }

    return 0;
}
