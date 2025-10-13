/*
 * getopt.c - POSIX getopt() implementation for Windows
 *
 * This is a minimal, public domain implementation of POSIX getopt()
 * for Windows compatibility.
 */

#include "getopt.h"
#include <string.h>
#include <stdio.h>

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = 0;

int getopt(int argc, char * const argv[], const char *optstring) {
    static int sp = 1;
    int c;
    const char *cp;

    if (sp == 1) {
        /* Check for end of options */
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return -1;
        }

        /* Handle "--" end of options marker */
        if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }

    optopt = c = argv[optind][sp];

    /* Check for invalid option character */
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr && *optstring != ':') {
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        }

        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }

    /* Check if option requires an argument */
    if (cp[1] == ':') {
        /* Option requires an argument */
        if (argv[optind][sp + 1] != '\0') {
            /* Argument is in same argv element */
            optarg = &argv[optind++][sp + 1];
        } else if (++optind >= argc) {
            /* Missing required argument */
            if (opterr && *optstring != ':') {
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            }
            sp = 1;
            return ((*optstring == ':') ? ':' : '?');
        } else {
            /* Argument is in next argv element */
            optarg = argv[optind++];
        }
        sp = 1;
    } else {
        /* Option does not require an argument */
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }

    return c;
}
