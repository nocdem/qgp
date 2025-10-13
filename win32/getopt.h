/*
 * getopt.h - POSIX getopt() for Windows
 *
 * Minimal getopt implementation for Windows compatibility.
 * Based on public domain implementations.
 */

#ifndef GETOPT_H
#define GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;
extern int optind;
extern int opterr;
extern int optopt;

int getopt(int argc, char * const argv[], const char *optstring);

#ifdef __cplusplus
}
#endif

#endif /* GETOPT_H */
