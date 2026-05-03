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
* misc.c                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>


/* own includes */
#include "misc.h"
#include "wrapper.h"
#include "error.h"
#include "http.h"


/* build whole attack url string: <baseurl>+<word>+[extension] */
char **build_urls(const char *url, char **wordlist, const size_t num_words,
                  char **extens, const size_t num_extens)
{
  char **urls = NULL, *fmtstr = "%s/%s%s";
  register size_t line_len = 0, url_len = 0, sum = 0, i = 0, j = 0, k = 0;

  /* check for ending '/' in url */
  url_len = strlen(url) - 1;
  if (url[url_len] == '/') {
    fmtstr = "%s%s%s";
  }

  /* total real urls. +1 slot for the trailing NULL terminator */
  sum = num_words * num_extens;
  urls = xcalloc(sum + 1, sizeof (char *));

  for (j = 0; j < num_extens; ++j) {
    for (k = 0; k < num_words; ++k) {
      line_len = snprintf(NULL, 0, fmtstr, url, wordlist[k], extens[j]) + 1;
      urls[i] = xcalloc(1, line_len);
      snprintf(urls[i], line_len, fmtstr, url, wordlist[k], extens[j]);
      ++i;
    }
  }

  /* mark end */
  urls[i] = NULL;

  return urls;
}


/* read lines from a file. kill <lastchar> with 0x00 if given. count lines.
 * uses a stack scratch buffer for fgets() and shrinks each kept line down to
 * its real length, which dramatically lowers heap usage on big wordlists */
char **read_lines(const char *filename, size_t line_len, size_t *num_lines,
                  const int lastchar)
{
  FILE *fp = NULL;
  char **lines = NULL;
  register size_t cur_len = 0, last = 0;

  /* just in case */
  *num_lines = 0;

  if ((fp = fopen(filename, "r")) == NULL) {
    return NULL;
  }

  /* let's set default then: 1KB */
  if (line_len == 0) {
    line_len = DEF_LINE_LEN;
  }

  /* scratch buffer reused across iterations - we copy out only what we need */
  char scratch[line_len];

  lines = xcalloc(1, sizeof (char *));
  while (fgets(scratch, line_len, fp) != NULL) {
    cur_len = strlen(scratch);
    if (cur_len != 0) {
      last = cur_len - 1;
      if (lastchar != 0 && scratch[last] == lastchar) {
        scratch[last] = 0x00; /* kill newline */
        cur_len = last;
      }
    }
    lines[*num_lines] = xcalloc(1, cur_len + 1);
    memcpy(lines[*num_lines], scratch, cur_len);
    ++(*num_lines);
    lines = xrealloc(lines, sizeof (char *) * (*num_lines + 1));
    lines[*num_lines] = NULL;
  }

  fclose(fp);

  return lines;
}


/* convert given string to upper-case or lower-case */
char *touplow(const char *str, const char *to)
{
  size_t i = 0;
  size_t len = strlen(str);
  char *newstr = NULL;
  int (*fptr)(int);

  /* +1 for trailing NUL; xcalloc zero-fills so we don't need to set it */
  newstr = xcalloc(len + 1, sizeof(char));

  if (!(strcmp(to, "up"))) {
    fptr = toupper;
  } else {
    fptr = tolower;
  }

  for (i = 0; i < len; i++) {
    newstr[i] = fptr((unsigned char) str[i]);
  }

  return newstr;
}


/* parse string with given delimiter and create a NULL-terminated
 * char**. unlike strtok() this preserves empty tokens, so input like
 * ",.bak" or ":foo" yields ["", ".bak"] / ["", "foo"] instead of
 * silently dropping the leading empty. caller keeps the input buffer
 * alive (we NUL-terminate in place and hand back interior pointers).
 * delim is a charset like strtok */
char **parse_str_token(char *str, const char *delim,
                       const unsigned char num_substr)
{
  char **parsed = NULL;
  int n = 0;
  char *p = NULL, *start = NULL;

  parsed = xcalloc(num_substr, sizeof(char *));

  if (str == NULL) {
    return parsed;
  }

  start = str;
  for (p = str; *p != '\0'; ++p) {
    if (strchr(delim, *p) != NULL) {
      if (n >= num_substr - 1) break;
      *p = '\0';
      parsed[n++] = start;
      start = p + 1;
    }
  }
  /* trailing token (or the whole string when no delim was hit). also
   * captures the empty tail in cases like "foo," */
  if (n < num_substr - 1) {
    parsed[n] = start;
  }

  return parsed;
}

/* parse string with given delimiter and create a long int *foo. */
long int *parse_str_toint_token(char *str, const char *delim,
                               const unsigned char num_substr)
{
  char **parsed = NULL;
  long int *iparsed;
  int i = 0;

  parsed = xcalloc(num_substr, sizeof(char *));
  iparsed = xcalloc(num_substr, sizeof(size_t));

  for (i = 0; i < num_substr - 1; ++i, str = NULL) {
    if ((parsed[i] = strtok(str, delim)) == NULL) {
      break;
    }
  }

  for (i = 0; i < num_substr - 1; ++i) {
    if (parsed[i]) {
      iparsed[i] = ATOI(parsed[i]);
    } else {
      break;
    }
  }

  free(parsed);

  return iparsed;
}


/* parse "<num>[suffix]" into bytes. accepts an optional trailing
 * K/M/G (case-insensitive) for 1024^1/1024^2/1024^3, default unit is
 * bytes. examples: "100", "10K", "5M", "1G". returns -1 on garbage,
 * negative or overflow */
long long parse_size(const char *s)
{
  long long val = 0;
  char *end = NULL;

  if (s == NULL || *s == '\0') {
    return -1;
  }

  errno = 0;
  val = strtoll(s, &end, 10);
  if (end == s || val < 0 || errno == ERANGE) {
    return -1;
  }

  /* allow exactly one suffix char then EOS, nothing else */
  if (*end != '\0') {
    char c = (char) tolower((unsigned char) *end);
    if (end[1] != '\0') {
      return -1;
    }
    switch (c) {
      case 'k': val *= 1024LL; break;
      case 'm': val *= 1024LL * 1024LL; break;
      case 'g': val *= 1024LL * 1024LL * 1024LL; break;
      default:  return -1;
    }
  }

  return val;
}

