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
* checks.c                                                                     *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>


/* own includes */
#include "checks.h"
#include "lulzbuster.h"
#include "error.h"
#include "http.h"
#include "misc.h"


/* static func prototypes. tri-state checks (true/false/ASK for '?') stay
 * unsigned char; everything else returns plain bool */
static bool check_url(const char *);
static unsigned char check_http_method(char *);
static bool check_file(const char *, int);
static bool check_num(const unsigned short int,
                      const unsigned short int);
static bool check_creds(const char *);
static unsigned char check_proxy(char *);
static bool check_port(const char *);
static unsigned char check_http_version(const char *);


/* checks, if required arguments were selected */
void check_args(opts_T *opts)
{
  if (opts->start_url == NULL) {
    free_lulzbuster(opts);
    err(E_TARGET);
  }

  return;
}


/* check for argument count */
void check_argc(int argc)
{
  if (argc < 2) {
    err(E_ARGC);
  }

  return;
}


/* check URL format */
static bool check_url(const char *target_url)
{
  register bool check_ok = true;
  char *scheme = NULL;
  CURLUcode rc = 0;
  CURLU *url = curl_url();

  rc = curl_url_set(url, CURLUPART_URL, target_url, 0);

  if (!rc) {
    rc = curl_url_get(url, CURLUPART_SCHEME, &scheme, 0);
    if (!rc) {
      if ((strcmp(scheme, "http") != 0) && (strcmp(scheme, "https") != 0)) {
        check_ok = false;
      }
    }
  } else {
    check_ok = false;
  }

  curl_free(scheme);
  curl_url_cleanup(url);

  return check_ok;
}


/* check HTTP request type */
static unsigned char check_http_method(char *http_method)
{
  register unsigned char check_ok = false;
  register size_t j = 0, len = strlen(http_method) + 1;
  char *http_methods[] = {
    HTTP_HEAD, HTTP_GET, HTTP_POST, HTTP_PUT, HTTP_DELETE, HTTP_OPTIONS,
  };

  /* abort immediately bullshit long was given */
  if (len > MAX_METHOD_LEN) {
    return false;
  }

  for (j = 0; j < ARRAY_SIZE(http_methods); j++) {
    if (http_method[0] == '?') {
      JSLOG("available HTTP requests types\n\n");
      for (j = 0; j < ARRAY_SIZE(http_methods); j++) {
        VSLOG(http_methods[j]);
        SLOG("\n");
      }
      SLOG("\n");
      check_ok = ASK;
      break;
    }
    if (!strcmp(http_method, http_methods[j])) {
      check_ok = true;
      break;
    }
  }

  return check_ok;
}


/* check if we can open the given file with the requested access mode.
 * for write checks on a non-existing file we touch it (empty) so we can
 * verify perms - launch_attack() will append to it later. previously
 * unlink()ed the file unconditionally which nuked any existing -l log */
static bool check_file(const char *file, int mode)
{
  register bool check_ok = false;
  FILE *fp = NULL;

  /* file does not exist yet but caller wants to write - try to create
   * an empty one so we can confirm write permission */
  if ((mode & W_OK) && access(file, F_OK) != 0) {
    fp = fopen(file, "a");
    if (fp == NULL) {
      return false;
    }
    fclose(fp);
  }

  /* check for given mode */
  if (access(file, mode) == 0) {
    check_ok = true;
  }

  return check_ok;
}


/* check if num exceeds MAX_* / lowers MIN_* */
static bool check_num(const unsigned short int num,
                      const unsigned short int val)
{
  register bool check_ok = false;

  switch (val) {
   case MAX_THRDS:
     check_ok = (num > MAX_THRDS) ? false : true;
     break;
   case MAX_DELAY: /* covers also conn and read timeout */
     check_ok = (num > MAX_DELAY) ? false : true;
     break;
   case MIN_GLOB_TIMEOUT:
     check_ok = (num != 0 && num < MIN_GLOB_TIMEOUT) ? false : true;
     break;
   case MAX_CONN_CACHE:
     check_ok = (num > MAX_CONN_CACHE) ? false : true;
     break;
   default:
     check_ok = true;
  }

  return check_ok;
}


/* check if credentials format is correct */
static bool check_creds(const char *str)
{
  register bool check_ok = false;

  if (str[0] && str[1]) {
    check_ok = true;
  }

  return check_ok;
}


/* check if correct scheme and <num> parts were given for proxy */
static unsigned char check_proxy(char *str)
{
  register unsigned char check_ok = true;
  register size_t i = 0, len = strlen(str) + 1;
  char tmpstr[len];
  char **pstr = NULL,
       *proxy_schemes[] = {
         PROXY_SCHEME_HTTP, PROXY_SCHEME_HTTPS, PROXY_SCHEME_SOCKS4,
         PROXY_SCHEME_SOCKS4A, PROXY_SCHEME_SOCKS5, PROXY_SCHEME_SOCKS5H
       };

  /* we don't want strtok() to fuck up our original string */
  strcpy(tmpstr, str);
  tmpstr[len - 1] = 0x00;

  pstr = parse_str_token(tmpstr, ":", 4);

  /* user asked for available proxy schemes */
  if (tmpstr[0] == '?') {
    free(pstr);
    JSLOG("available proxy schemes\n\n");
    for (i = 0; i < ARRAY_SIZE(proxy_schemes); ++i) {
      VSLOG(proxy_schemes[i]);
      SLOG("\n");
    }
    SLOG("\n");
    return ASK;
  }

  /* bail early if no scheme token at all - strtok returns NULL on
   * input like "::" or ":foo" and the strcmp below would deref NULL */
  if (pstr[0] == NULL) {
    free(pstr);
    return false;
  }

  /* too short or too long */
  if (pstr[3] != NULL) {
    check_ok = false;
  }

  /* wrong scheme */
  if ((strcmp(pstr[0], "http") != 0) && (strcmp(pstr[0], "https") != 0) &&
      (strcmp(pstr[0], "socks4") != 0) && (strcmp(pstr[0], "socks4a") != 0) &&
      (strcmp(pstr[0], "socks5") != 0) && (strcmp(pstr[0], "socks5h") != 0)) {
    check_ok = false;
  }

  /* wrong port */
  if (pstr[2]) {
    if (!check_port(pstr[2]))
      check_ok = false;
  } else {
    check_ok = false;
  }

  free(pstr);

  return check_ok;
}


/* check if port is a valid TCP port (1..65535). port 0 is rejected
 * because connecting to it makes no sense for a proxy */
static bool check_port(const char *port)
{
  register bool check_ok = true;
  long int p = 0;

  p = ATOI(port);

  if (p <= 0 || p > 65535) {
    check_ok = false;
  }

  return check_ok;
}


/* check if a valid http version was specified */
static unsigned char check_http_version(const char *ver)
{
  register unsigned char check_ok = true;
  char *http_vers[] = { HTTP_VER_10, HTTP_VER_11, HTTP_VER_20, HTTP_VER_30 };
  register size_t i = 0;

  if (ver[0] == '?') {
    JSLOG("available http versions\n\n");
    for (i = 0; i < ARRAY_SIZE(http_vers); ++i) {
      VSLOG(http_vers[i]);
      SLOG("\n");
    }
    SLOG("\n");
    return ASK;
  }

  for (i = 0; i < ARRAY_SIZE(http_vers); ++i) {
    if ((strcmp(ver, HTTP_VER_10) != 0) && (strcmp(ver, HTTP_VER_11) != 0) &&
        (strcmp(ver, HTTP_VER_20) != 0) && (strcmp(ver, HTTP_VER_30) != 0)) {
      check_ok = false;
    }
  }

  return check_ok;
}


/* perform basic checks on all cmdline opts */
void check_opts(opts_T *opts)
{
  register unsigned char check_ok = false;

  /* check if a correct/full HTTP url was given for target start url */
  if (!check_url(opts->start_url)) {
    free_lulzbuster(opts);
    err(E_URL);
  }

  /* check if correct http method was given */
  check_ok = check_http_method(opts->http_method);
  if (!check_ok) {
    free_lulzbuster(opts);
    err(E_METH);
  }
  if (check_ok == ASK) {
    free_lulzbuster(opts);
    __GAME_OVER;
    __EXIT_SUCCESS;
  }

  /* check proxy addr was supplied correctly. */
  if (opts->proxy) {
    check_ok = check_proxy(opts->proxy);
    if (!check_ok) {
      free_lulzbuster(opts);
      err(E_PROXY_ADDR);
    }
    if (check_ok == ASK) {
      free_lulzbuster(opts);
      __GAME_OVER;
      __EXIT_SUCCESS;
    }
  }

  /* check if user:pass was exactly supplied */
  if (opts->creds) {
    if (!check_creds(opts->creds)) {
      free_lulzbuster(opts);
      err(E_CREDS);
    }
  }

  /* check if user:pass (proxy) was exactly supplied */
  if (opts->proxy_creds) {
    if (!check_creds(opts->proxy_creds)) {
      free_lulzbuster(opts);
      err(E_PCREDS);
    }
  }

  /* check if valid http version was selected */
  if (opts->http_version) {
    check_ok = check_http_version(opts->http_version);
    if (!check_ok) {
      free_lulzbuster(opts);
      err(E_HTTP_VER);
    }
    if (check_ok == ASK) {
      free_lulzbuster(opts);
      __GAME_OVER;
      __EXIT_SUCCESS;
    }
  }

  /* check max threads value */
  if (!check_num(opts->threads, MAX_THRDS)) {
    err(W_THRDS);
  }

  /* check max connection cache size value */
  if (!check_num(opts->conn_cache, MAX_CONN_CACHE)) {
    err(W_MAXCONN_CACHE);
  }

  /* check max request delay, connect and read timeout value */
  if (!check_num(opts->delay, MAX_DELAY)) {
    err(W_DELAY);
  }

  /* check max global timeout value */
  if (!check_num(opts->glob_timeout, MIN_GLOB_TIMEOUT)) {
    err(W_GLOB_NUM);
  }

  /* check if we can read wordlist */
  if (!check_file(opts->wordlist, R_OK)) {
    free_lulzbuster(opts);
    err(E_RFILE);
  }

  /* check if we can write to logfile */
  if (opts->logfile) {
    if (!check_file(opts->logfile, W_OK)) {
      free_lulzbuster(opts);
      err(E_WFILE);
    }
  }

  /* mTLS files: cert + key must be readable. without these checks
   * curl would fail mid-perform with a less obvious error code */
  if (opts->cert_file && !check_file(opts->cert_file, R_OK)) {
    free_lulzbuster(opts);
    err(E_RCERT);
  }
  if (opts->key_file && !check_file(opts->key_file, R_OK)) {
    free_lulzbuster(opts);
    err(E_RKEY);
  }

  return;
}

