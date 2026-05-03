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
* log.c                                                                        *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>


/* own includes */
#include "log.h"
#include "wrapper.h"


/* color ptrs - default to the ANSI sequences. init_colors() flips them
 * to "" when colors should be off. defined here so changing them later
 * propagates to every callsite via the LOG macros */
const char *CBLUE   = "\033[1;34;10m";
const char *CRED    = "\033[1;31;10m";
const char *CYELLOW = "\033[1;33;10m";
const char *CGREEN  = "\033[1;32;10m";
const char *CCYAN   = "\033[1;36;10m";
const char *CBOLD   = "\033[1;37;10m";
const char *CDIM    = "\033[2m";
const char *CRESET  = "\033[0m";


void init_colors(int enable)
{
  if (enable) {
    CBLUE   = "\033[1;34;10m";
    CRED    = "\033[1;31;10m";
    CYELLOW = "\033[1;33;10m";
    CGREEN  = "\033[1;32;10m";
    CCYAN   = "\033[1;36;10m";
    CBOLD   = "\033[1;37;10m";
    CDIM    = "\033[2m";
    CRESET  = "\033[0m";
  } else {
    CBLUE = CRED = CYELLOW = CGREEN = CCYAN = CBOLD = CDIM = CRESET = "";
  }
}


/* hit-line code colorizer. green=2xx, cyan=3xx, yellow=4xx, red=5xx,
 * dim for anything else (HTTP_ZERO etc). returns a runtime-flippable
 * ptr so it auto-vanishes when colors are disabled */
const char *code_color(long code)
{
  if (code >= 200 && code < 300) return CGREEN;
  if (code >= 300 && code < 400) return CCYAN;
  if (code >= 400 && code < 500) return CYELLOW;
  if (code >= 500 && code < 600) return CRED;
  return CDIM;
}


/* RFC4180-ish CSV: only quote if the field has a comma, double-quote
 * or newline. doubles internal quotes when quoting */
static int csv_needs_quote(const char *s)
{
  for (; *s; ++s) {
    if (*s == ',' || *s == '"' || *s == '\n' || *s == '\r') return 1;
  }
  return 0;
}


static void csv_write_field(FILE *fp, const char *s)
{
  if (!csv_needs_quote(s)) {
    fputs(s, fp);
    return;
  }
  fputc('"', fp);
  for (; *s; ++s) {
    if (*s == '"') fputc('"', fp);
    fputc(*s, fp);
  }
  fputc('"', fp);
}


/* JSON string emitter. escapes the small set of chars JSON requires;
 * control bytes go to \u00XX */
static void json_write_string(FILE *fp, const char *s)
{
  fputc('"', fp);
  for (; *s; ++s) {
    unsigned char c = (unsigned char) *s;
    switch (c) {
      case '"':  fputs("\\\"", fp); break;
      case '\\': fputs("\\\\", fp); break;
      case '\b': fputs("\\b",  fp); break;
      case '\f': fputs("\\f",  fp); break;
      case '\n': fputs("\\n",  fp); break;
      case '\r': fputs("\\r",  fp); break;
      case '\t': fputs("\\t",  fp); break;
      default:
        if (c < 0x20) fprintf(fp, "\\u%04x", c);
        else          fputc(c, fp);
    }
  }
  fputc('"', fp);
}


void log_csv_header(FILE *fp)
{
  fprintf(fp, "code,size,lines,words,resp_time_s,content_type,url\n");
}


void log_hit(FILE *fp, unsigned char fmt, long code, double bytes, char suf,
             unsigned long long real_size, unsigned long lines,
             unsigned long words, double rtime, const char *ctype,
             const char *url)
{
  /* hold the FILE lock across the whole row so concurrent workers can't
   * interleave parts of a CSV/JSONL row mid-write. flockfile() is
   * POSIX, recursive, and what stdio uses internally per-call - we just
   * widen the critical section to the row scope */
  flockfile(fp);
  switch (fmt) {
    case LOG_FMT_CSV:
      /* CSV gets the FULL ctype (no truncation) since CSV is for tooling
       * not eyeballing - downstream parsers handle long fields fine */
      fprintf(fp, "%ld,%llu,%lu,%lu,%lf,",
              code, real_size, lines, words, rtime);
      csv_write_field(fp, ctype);
      fputc(',', fp);
      csv_write_field(fp, url);
      fputc('\n', fp);
      break;
    case LOG_FMT_JSONL:
      /* JSONL also gets the full ctype for the same reason */
      fprintf(fp, "{\"code\":%ld,\"size\":%llu,\"lines\":%lu,\"words\":%lu,"
              "\"resp_time_s\":%lf,\"content_type\":",
              code, real_size, lines, words, rtime);
      json_write_string(fp, ctype);
      fputs(",\"url\":", fp);
      json_write_string(fp, url);
      fputs("}\n", fp);
      break;
    default: /* LOG_FMT_TEXT - same shape as the stderr table. column
              * widths match the HEADLINE in inc/attack.h: 4-wide code
              * (so "code" header fits), 5-wide size, 9-wide real_size,
              * 6-wide lines/words, 20-wide ctype (CTYPE_COL_WIDTH),
              * 9-wide resp time. eyeball both if you change anything */
      fprintf(fp, "[*] %-4ld | %4.0lf%c | %8lluB | %5luL | %5luW | %-*s "
              "| %lfs | %s\n",
              code, bytes, suf, real_size, lines, words,
              CTYPE_COL_WIDTH, ctype, rtime, url);
      break;
  }
  funlockfile(fp);
}


void emit_hit(FILE *const logs[LOG_FMT_COUNT], const char *url,
              long code, double bytes, char suf,
              unsigned long long real_size, unsigned long lines,
              unsigned long words, double rtime, const char *ctype)
{
  int f = 0;
  char tbuf[CTYPE_COL_WIDTH + 1]; /* table-formatted ctype copy */
  const char *raw = (ctype != NULL && ctype[0] != '\0') ? ctype : "-";
  size_t i = 0;

  /* normalize the ctype shown in the stderr table + LOG_FMT_TEXT:
   * strip any '; charset=...' suffix (servers tack it on inconsistently
   * and it eats column space without adding signal), then hard-truncate
   * to CTYPE_COL_WIDTH so the table stays aligned. CSV/JSONL keep the
   * untouched value via log_hit() since those formats are for tools */
  for (; i < CTYPE_COL_WIDTH && raw[i] != '\0' &&
         raw[i] != ';' && raw[i] != ' '; ++i) {
    tbuf[i] = raw[i];
  }
  tbuf[i] = '\0';

  /* stderr table: leading \r overwrites the "scanning X / Y" status
   * line that the worker just printed. code field is colored by class
   * (2xx/3xx/4xx/5xx); rest stays plain so the table reads as a table.
   * code is %-4ld (left-aligned in 4 chars) so the "code" header in
   * HEADLINE fits and pipes line up vertically with the data rows */
  fprintf(stderr,
          "%s\r[*] %s%s%-4ld%s | %4.0lf%c | %8lluB | %5luL | %5luW | "
          "%-*s | %lfs | %s\n",
          CGREEN, CRESET, code_color(code), code, CRESET, bytes, suf,
          real_size, lines, words, CTYPE_COL_WIDTH, tbuf, rtime, url);

  for (f = 0; f < LOG_FMT_COUNT; ++f) {
    if (logs[f] != NULL) {
      /* TEXT format gets the truncated table version for visual parity
       * with stderr; CSV/JSONL get the raw full ctype */
      const char *pass = (f == LOG_FMT_TEXT) ? tbuf : raw;
      log_hit(logs[f], (unsigned char) f, code, bytes, suf,
              real_size, lines, words, rtime, pass, url);
    }
  }
}


/* derive a filesystem-safe filename stem from a URL using the rules
 * the user wants:
 *   '://'         -> '-'
 *   '.' / ':'     -> '-'    (host-name dots, port colon)
 *   first '/'     -> '_'    (host -> path boundary)
 *   subseq. '/'   -> '-'    (path slashes)
 *   trailing '/' or other separators are stripped before .ext
 *   anything else not in [A-Za-z0-9_-] is collapsed to '-' so we
 *   don't end up with weird filenames on query strings/fragments */
char *derive_logfile(const char *url, const char *ext)
{
  size_t ulen = strlen(url);
  size_t elen = strlen(ext);
  /* upper bound: every input char fits 1:1 in output (we only ever
   * substitute or drop), plus '.' + ext + NUL */
  char *buf = xcalloc(1, ulen + elen + 2);
  size_t i = 0, n = 0;
  bool in_path = false;

  while (i < ulen) {
    /* collapse "://" to a single '-' (otherwise "https" + ":" + "/" +
     * "/" would produce "https---" once colons/slashes are replaced) */
    if (!in_path && i + 2 < ulen &&
        url[i] == ':' && url[i + 1] == '/' && url[i + 2] == '/') {
      buf[n++] = '-';
      i += 3;
      continue;
    }
    if (url[i] == '/') {
      buf[n++] = in_path ? '-' : '_';
      in_path = true;
      ++i;
      continue;
    }
    if (url[i] == '.' || url[i] == ':') {
      buf[n++] = '-';
      ++i;
      continue;
    }
    {
      unsigned char c = (unsigned char) url[i++];
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_') {
        buf[n++] = (char) c;
      } else {
        buf[n++] = '-';
      }
    }
  }
  /* trim trailing separators - covers root '/' (-> '_'), repeated
   * '/'s, and any sanitized garbage at the tail */
  while (n > 0 && (buf[n - 1] == '_' || buf[n - 1] == '-')) {
    buf[--n] = '\0';
  }

  buf[n++] = '.';
  memcpy(buf + n, ext, elen);
  buf[n + elen] = '\0';

  return buf;
}
