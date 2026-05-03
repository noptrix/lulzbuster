/*******************************************************************************
*                ____                     _ __                                 *
*     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           *
*    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           *
*   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            *
*                                            /___/ team                        *
*                                                                              *
* lulzbuster                                                                   *
* A very fast and smart web directory and file enumeration tool written in C.  *
*                                                                              *
* FILE                                                                         *
* log.h                                                                        *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef LOG_H
#define LOG_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <stdio.h>


/* own includes */


/*******************************************************************************
 * VARS
 ******************************************************************************/


/* runtime color ptrs - point to the ANSI escape sequence when colors
 * are on, or "" when off. flipped once at startup by init_colors().
 * runtime instead of compile-time so we can honor -N, isatty() and
 * the NO_COLOR env var without a recompile */
extern const char *CBLUE;
extern const char *CRED;
extern const char *CYELLOW;
extern const char *CGREEN;
extern const char *CCYAN;
extern const char *CBOLD;
extern const char *CDIM;
extern const char *CRESET;


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* message prefixes */
#define PJOB  "[+] "
#define PGOOD "[*] "
#define PVERB "    > "
#define PWARN "[!] "
#define PERR  "[-] "


/* simple one-format logging macros for colored output:
 * : stdout, S: stderr, C: custom. trailing semicolon NOT included so
 * callers like `if (x) JLOG(...);` work the same as before. ##__VA_ARGS__
 * (gcc/clang extension) so 1-arg calls still compile */
#define LOG(...)         fprintf(stdout, __VA_ARGS__)
#define SLOG(...)        fprintf(stderr, __VA_ARGS__)
#define CLOG(file, ...)  fprintf(file, __VA_ARGS__)
#define JLOG(fmt, ...)   fprintf(stdout, "%s" PJOB "%s" fmt, CBLUE, CRESET, ##__VA_ARGS__)
#define GLOG(fmt, ...)   fprintf(stdout, "%s" PGOOD "%s" fmt, CGREEN, CRESET, ##__VA_ARGS__)
#define VLOG(fmt, ...)   fprintf(stdout, "%s" PVERB "%s" fmt, CDIM, CRESET, ##__VA_ARGS__)
#define JSLOG(fmt, ...)  fprintf(stderr, "%s" PJOB "%s" fmt, CBLUE, CRESET, ##__VA_ARGS__)
#define GSLOG(fmt, ...)  fprintf(stderr, "%s" PGOOD "%s" fmt, CGREEN, CRESET, ##__VA_ARGS__)
#define VSLOG(s)         fprintf(stderr, "%s" PVERB "%s%s", CDIM, CRESET, s)
#define WSLOG(fmt, ...)  fprintf(stderr, "%s" PWARN "%s" fmt, CYELLOW, CRESET, ##__VA_ARGS__)
#define ESLOG(fmt, ...)  fprintf(stderr, "%s" PERR "%s" fmt, CRED, CRESET, ##__VA_ARGS__)


/* shorten 'game started' / 'game over' call */
#define __GAME_START  JSLOG("game started\n\n");
#define __GAME_OVER   JSLOG("game over\n");


/* output formats for the hit logfile (-O). LOG_FMT_TEXT mirrors the
 * stderr table for grep-friendliness, CSV/JSONL are for tooling. the
 * enum values double as indices into opts_T.log_paths[] / job->logs[],
 * the BIT_* masks are for opts_T.log_formats (multi-format support
 * via comma-separated -O list or -O all) */
#define LOG_FMT_TEXT       0
#define LOG_FMT_CSV        1
#define LOG_FMT_JSONL      2
#define LOG_FMT_COUNT      3
#define LOG_FMT_BIT_TEXT   (1u << LOG_FMT_TEXT)
#define LOG_FMT_BIT_CSV    (1u << LOG_FMT_CSV)
#define LOG_FMT_BIT_JSONL  (1u << LOG_FMT_JSONL)
#define LOG_FMT_BIT_ALL    (LOG_FMT_BIT_TEXT | LOG_FMT_BIT_CSV | \
                            LOG_FMT_BIT_JSONL)


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* init color ptrs based on -N flag, NO_COLOR env, and stderr-isatty.
 * call once during startup before any output. enable=0 -> all colors
 * become "" (no ANSI emitted) */
void init_colors(int enable);

/* pick a color ptr based on http response code class (2xx/3xx/4xx/5xx).
 * used by __HIT to colorize the code field in hit lines */
const char *code_color(long code);

/* width of the content-type column in the stderr table + LOG_FMT_TEXT
 * file output. picked so common values fit ('text/html',
 * 'application/json', 'application/javascript') without breaking the
 * column. longer values (e.g. 'application/vnd.api+json; charset=utf-8')
 * get the ;-suffix stripped and then truncated to this width */
#define CTYPE_COL_WIDTH  20

/* write a hit line to the logfile in the chosen format. mirrors the
 * stderr table for LOG_FMT_TEXT, emits a CSV row for LOG_FMT_CSV and
 * a JSONL object for LOG_FMT_JSONL. fp is assumed open + writable.
 * ctype is the response Content-Type ('-' when the server didn't send
 * one); already pre-truncated by emit_hit before reaching here for the
 * stderr/text formats */
void log_hit(FILE *fp, unsigned char fmt, long code, double bytes, char suf,
             unsigned long long real_size, unsigned long lines,
             unsigned long words, double rtime, const char *ctype,
             const char *url);

/* emit a hit: colored stderr table line + a row in each open logfile
 * (one per format slot, NULL slots skipped). called from worker
 * threads, internally synchronized via flockfile in log_hit().
 * ctype may be NULL; emit_hit normalizes to "-" and strips any
 * '; charset=...' suffix for the table/text presentations */
void emit_hit(FILE *const logs[LOG_FMT_COUNT], const char *url,
              long code, double bytes, char suf,
              unsigned long long real_size, unsigned long lines,
              unsigned long words, double rtime, const char *ctype);

/* write the CSV column header. only emitted when the file is empty
 * (ftell == 0) so appending across runs doesn't duplicate */
void log_csv_header(FILE *fp);

/* derive a logfile name from a URL. examples:
 *   https://www.nullsecurity.net/        -> https-www-nullsecurity-net.<ext>
 *   https://www.nullsecurity.net/foo     -> https-www-nullsecurity-net_foo.<ext>
 *   https://x.org:1337/foo/bar           -> https-x-org-1337_foo-bar.<ext>
 * caller frees */
char *derive_logfile(const char *url, const char *ext);


#endif
