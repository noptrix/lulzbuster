/*******************************************************************************
*                ____                     _ __                                 *
*     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           *
*    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           *
*   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            *
*                                            /___/ team                        *
*                                                                              *
* lulzbuster                                                                   *
* A very fast and smart web-dir/file enumeration tool written in C.            *
*                                                                              *
* FILE                                                                         *
* misc.c                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */


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

  /* sum items: words * extensions + 1 (NULL ptr for END) */
  sum = num_words * num_extens + 1;

  /* we definetely force to end URL with '/' but we ignore multiple '/'
   * appended to start url via cmdline. */
  urls = xcalloc(sum + num_extens, sizeof (char *));
  while (i < sum) {
    for (j = 0; j < num_extens; ++j) {
      for (k = 0; k < num_words + 1; ++k) {
        line_len = snprintf(NULL, 0, fmtstr, url, wordlist[k], extens[j]) + 1;
        urls[i] = xcalloc(1, line_len);
        snprintf(urls[i], line_len, fmtstr, url, wordlist[k], extens[j]);
        ++i;
      }
    }
  }

  /* cheat a bit and mark end */
  urls[i] = NULL;

  return urls;
}


/* read lines from a file. kill <lastchar> with 0x00 if given. count lines */
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

  lines = xcalloc(1, sizeof (char *));
  do {
    lines[*num_lines] = xcalloc(1, line_len);
    if (fgets(lines[*num_lines], line_len, fp) == NULL) {
      fclose(fp);
      return lines;
    }
    cur_len = strlen(lines[*num_lines]);
    last = cur_len - 1;
    if (cur_len != 0) {
      if (lastchar != 0 && (lines[*num_lines][last] == lastchar)) {
        lines[*num_lines][last] = 0x00; /* kill newline */
      }
    }
    ++(*num_lines);
    lines = xrealloc(lines, sizeof (char *) * (*num_lines + 1));
  } while (!feof(fp));

  fclose(fp);

  return lines;
}


/* convert given string to upper-case or lower-case */
char *touplow(const char *str, const char *to)
{
  size_t i = 0;
  size_t len = strlen(str) + 1;
  char *newstr = NULL;
  int (*fptr)(const int);

  newstr = xcalloc(len, sizeof (char *));

  if (!(strcmp(to, "up"))) {
    fptr = toupper;
  } else {
    fptr = tolower;
  }

  for (i = 0; i < len; i++) {
    newstr[i] = fptr(str[i]);
  }

  newstr[len] = 0x00;

  return newstr;
}


/* parse string with given delimiter and create a char **foo. */
char **parse_str_token(char *str, const char *delim,
                       const unsigned char num_substr)
{
  char **parsed = NULL;
  int i = 0;

  parsed = xcalloc(num_substr, sizeof(char *));

  for (i = 0; i < num_substr - 1; ++i, str = NULL) {
    if ((parsed[i] = strtok(str, delim)) == NULL) {
      break;
    }
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

