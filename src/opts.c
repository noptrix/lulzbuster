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
* opts.c                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>


/* own includes */
#include "opts.h"
#include "lulzbuster.h"
#include "error.h"
#include "help.h"
#include "http.h"
#include "misc.h"


/* set static http (curl) options. i wanted to refactor and make this dynamic
 * using a structure and for() to assign and call curl_easy_setopt(). problem
 * is that there are various data types needed. casting etc. here is NO-WAY. */
unsigned char set_http_options(opts_T *opts)
{
  /* enable tcp fastopen */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_TCP_FASTOPEN, 1L) != CURLE_OK) {
    err(E_CURL_TCPFAST);
    return FALSE;
  }

  /* set dns caching to remain forever */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_DNS_CACHE_TIMEOUT, -1L) != \
      CURLE_OK) {
    err(E_CURL_DNSCACHE);
    return FALSE;
  }

  /* send curl data (http responses) to our write_cb() callback */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_WRITEFUNCTION, write_cb) != \
      CURLE_OK) {
    err(E_CURL_WF);
    return FALSE;
  }

  /* max connect cache pool size */
  if (opts->conn_cache) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_MAXCONNECTS,
                         opts->conn_cache) != CURLE_OK) {
      err(E_CURL_MAXCONNS);
      return FALSE;
    }
  }

  /* ssl/tls shit */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_SSL_VERIFYPEER,
                       opts->in_ssl) != CURLE_OK) {
    err(E_CURL_SSL_PEER);
    return FALSE;
  }
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_SSL_VERIFYHOST,
                       opts->in_ssl) != CURLE_OK) {
    err(E_CURL_SSL_HOST);
    return FALSE;
  }

  /* user-agent */
  if (opts->useragent) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_USERAGENT,
                         opts->useragent) != CURLE_OK) {
      err(E_CURL_UAGENT);
      return FALSE;
    }
  }

  /* http request method. no body read if http method "HEAD" was chosen,
   * otherwise too slow!  */
  if (opts->http_method) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_CUSTOMREQUEST,
                         opts->http_method) != CURLE_OK) {
      err(E_CURL_CREQUEST);
      return FALSE;
    }
    if (strcmp(opts->http_method, "HEAD") == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_NOBODY, 1L) != CURLE_OK) {
        err(E_CURL_NOBODY);
        return FALSE;
      }
    }
  }

  /* follow redirects. */
  if (opts->follow_redir) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_FOLLOWLOCATION,
                         opts->follow_redir) != CURLE_OK) {
      err(E_CURL_FOLLOW);
      return FALSE;
    }
  }
  if (opts->follow_redir_level) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_MAXREDIRS,
                         opts->follow_redir_level) != CURLE_OK) {
      err(E_CURL_MAXRDIRS);
      return FALSE;
    }
  }

  /* auto referrer value update */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_AUTOREFERER,
                       opts->autoref) != CURLE_OK) {
    err(E_CURL_AREFER);
    return FALSE;
  }

  /* connection timeout */
  if (opts->conn_timeout) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_CONNECTTIMEOUT,
                         opts->conn_timeout) != CURLE_OK) {
      err(E_CURL_TIMEOUT);
      return FALSE;
    }
  }

  /* request timeout */
  if (opts->req_timeout) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_TIMEOUT,
                         opts->req_timeout) != CURLE_OK) {
      err(E_CURL_TIMEOUT);
      return FALSE;
    }
  }

  /* http auth: creds + http auth types to support */
  if (opts->creds) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_USERPWD, opts->creds) != \
        CURLE_OK) {
      err(E_CURL_USERPWD);
      return FALSE;
    }
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTPAUTH, CURLAUTH_ANY) != \
        CURLE_OK) {
      err(E_CURL_HTTPAUTH);
      return FALSE;
    }
  }

  /* disable the curl's default Accept header */
  opts->curl->list = curl_slist_append(opts->curl->list, "Accept:");
  if (opts->curl->list == NULL) {
    err(E_CURL_SLIST);
    return FALSE;
  }

  /* set custom headers */
  if (opts->http_header) {
    opts->curl->list = curl_slist_append(opts->curl->list, opts->http_header);
    if (opts->curl->list == NULL) {
      err(E_CURL_SLIST);
      return FALSE;
    }
  }

  /* enable custom headers */
  if (opts->curl->list) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTPHEADER,
                         opts->curl->list) != CURLE_OK) {
      err(E_CURL_HTTPHDR);
      return FALSE;
    }
  }

  /* proxy shit */
  if (opts->proxy) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_PROXY, opts->proxy) != \
        CURLE_OK) {
      err(E_CURL_PROXY);
      return FALSE;
    }
    if (opts->proxy_creds) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_PROXYAUTH, CURLAUTH_ANY) != \
          CURLE_OK) {
        err(E_CURL_PAUTH);
        return FALSE;
      }
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_PROXYUSERPWD,
                           opts->proxy_creds) != CURLE_OK) {
        err(E_CURL_PCREDS);
        return FALSE;
      }
    }
  }

  /* http version */
  if (opts->http_version) {
    if (strcmp(opts->http_version, HTTP_VER_10) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_1_0) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return FALSE;
      }
    }
    if (strcmp(opts->http_version, HTTP_VER_11) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_1_1) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return FALSE;
      }
    }
    if (strcmp(opts->http_version, HTTP_VER_20) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_2) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return FALSE;
      }
    }
#ifndef LAME
    if (strcmp(opts->http_version, HTTP_VER_30) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_3) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return FALSE;
      }
    }
#endif
  }

  /* dns server to use instead of system ones */
  if (opts->nameserver) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_DNS_SERVERS,
                         opts->nameserver) != CURLE_OK) {
      err(W_CURL_DNS);
    }
  }

  /* shared object options */
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_SHARE,
                        CURL_LOCK_DATA_DNS) != CURLSHE_OK) {
    err(E_CURLSH_LDNS);
    return FALSE;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_SHARE,
                        CURL_LOCK_DATA_SSL_SESSION) != CURLSHE_OK) {
    err(E_CURLSH_SSL);
    return FALSE;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_SHARE,
                        CURL_LOCK_DATA_CONNECT) != CURLSHE_OK) {
    err(E_CURLSH_CONN);
    return FALSE;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_LOCKFUNC, lock_cb) != \
      CURLSHE_OK) {
    err(E_CURLSH_LF);
    return FALSE;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_UNLOCKFUNC, unlock_cb) != \
      CURLSHE_OK) {
    err(E_CURLSH_ULF);
    return FALSE;
  }

  return TRUE;
}


/* set extensions and return num extensions */
void set_extensions(opts_T *opts)
{
  char **tptr = NULL;
  register size_t i = 0;

  /* count num extensions. if none given add a ""-extension to fool */
  if (opts->extens != NULL) {
    for (i = 0, tptr = opts->extens; *tptr != NULL; ++tptr, ++i);
    opts->num_extens = i;
  } else {
    opts->extens = xcalloc(1, sizeof (char *));
    opts->extens[0] = "";
    opts->num_extens = 1; /* set one for ""-extension. again just to cheat */
  }

  return;
}


/* set attack_urls, count final urls and count http excluded codes */
void set_attack_urls(opts_T *opts)
{
  char **tmpwords = NULL, **tptr = NULL;
  register size_t i = 0;
  size_t num_words = 0;

  /* read in wordlist file */
  tmpwords = read_lines(opts->wordlist, 0, &num_words, '\n');

  /* we know that some fuckups occured if 1st item is NULL. free() shit */
  if (tmpwords[0] == NULL) {
    free(tmpwords);
    free_lulzbuster(opts);
    err(E_WLIST_RLN);
  }

  /* build attack urls */
  opts->attack_urls = build_urls(opts->start_url, tmpwords, num_words,
                                 opts->extens, opts->num_extens);

  /* get num attack_urls */
  for (tptr = opts->attack_urls; *tptr != NULL; ++tptr,
       ++opts->num_attack_urls);

  /* get num http excluded codes */
  for (i = 0; opts->http_ex_codes[i] != 0; ++i, ++opts->num_http_ex_codes);

  /* we are done with tmpwords. free() that shit */
  for (i = 0; i < num_words + 1; ++i) {
    free(tmpwords[i]);
  }
  free(tmpwords);

  return;
}


/* set default options */
void set_default_opts(opts_T *opts)
{
  /* default http status codes to exclude. */
  opts->http_ex_codes = xcalloc(7, sizeof(long unsigned int));
  opts->http_ex_codes[0] = HTTP_BAD_REQUEST;
  opts->http_ex_codes[1] = HTTP_NOT_FOUND;
  opts->http_ex_codes[2] = HTTP_INTERNAL_SERVER_ERROR;
  opts->http_ex_codes[3] = HTTP_NOT_IMPLEMENTED;
  opts->http_ex_codes[4] = HTTP_BAD_GATEWAY;
  opts->http_ex_codes[5] = HTTP_SERVICE_UNAVAILABLE;
  opts->http_ex_codes[6] = HTTP_ZERO;

  opts->http_method = touplow(DEF_HTTP_METHOD, "up"); /* because of free() */
  opts->follow_redir_level = DEF_FOLLOW_REDIR_LEVEL;
  opts->wordlist = DEF_WORDLIST;
  opts->useragent = DEF_USERAGENT;
  opts->rand_ua = DEF_RAND_UA;
  opts->autoref = DEF_AUTOREF_UPDATE;
  opts->threads = DEF_THREADS;
  opts->conn_cache = DEF_CONN_CACHE;
  opts->delay = DEF_DELAY;
  opts->conn_timeout = DEF_CONN_TIMEOUT;
  opts->req_timeout = DEF_REQ_TIMEOUT;
  opts->glob_timeout = DEF_GLOB_TIMEOUT;
  opts->in_ssl = DEF_IN_SSL;
  opts->smart = FALSE;
  opts->nameserver = DEF_NAMESERVER;

  return;
}


/* parse command line opts and run misc routines */
void parse_opts(int argc, char *argv[], opts_T *opts)
{
  int c = 0;
  opterr = 0;         /* STFU while errors occur within getopt() */

  while ((c = getopt(argc, argv,
    "s:h:x:fF:u:Uc:a:rj:D:C:R:T:t:g:w:A:p:P:iSn:l:vXVH")) != -1) {
    switch (c) {
     case 's':
       opts->start_url = optarg;
       break;
     case 'h':
       free(opts->http_method); /* allocated before in set_default_opts() */
       opts->http_method = touplow(optarg, "up");
       break;
     case 'x':
       free(opts->http_ex_codes); /* allocated before in set_default_opts() */
       opts->http_ex_codes = parse_str_toint_token(optarg, ",",
                                                   MAX_HTTP_STATUS_CODES);
       break;
     case 'f':
       opts->follow_redir = ON;
       break;
     case 'F':
       opts->follow_redir_level = ATOI(optarg);
       break;
     case 'u':
       opts->useragent = optarg;
       break;
     case 'U':
       opts->rand_ua = ON;
       break;
     case 'c':
       opts->http_header = optarg;
       break;
     case 'a':
       opts->creds = optarg;
       break;
     case 'r':
       opts->autoref = ON;
       break;
     case 'j':
       opts->http_version = optarg;
       break;
     case 'D':
       opts->delay = (unsigned int) ATOI(optarg);
       break;
     case 'C':
       opts->conn_timeout = (unsigned short int) ATOI(optarg);
       break;
     case 'R':
       opts->req_timeout = (unsigned short int) ATOI(optarg);
       break;
     case 'T':
       opts->glob_timeout = (unsigned short int) ATOI(optarg);
       break;
     case 't':
       opts->threads = (unsigned short int) ATOI(optarg);
       break;
     case 'g':
       opts->conn_cache = (long) ATOI(optarg);
       break;
     case 'w':
       opts->wordlist = optarg;
       break;
     case 'A':
       opts->extens = parse_str_token(optarg, ",", MAX_EXTENSIONS);
       break;
     case 'p':
       opts->proxy = optarg;
       break;
     case 'P':
       opts->proxy_creds = optarg;
       break;
     case 'i':
       opts->in_ssl = ON;
       break;
     case 'S':
       opts->smart = TRUE;
       break;
     case 'n':
       opts->nameserver = optarg;
       break;
     case 'l':
       opts->logfile = optarg;
       break;
     case 'X':
       print_useragents();
       free_lulzbuster(opts);
       __GAME_OVER;
       __EXIT_SUCCESS;
       break;
     case 'V':
       JSLOG(VERSION"\n");
       free_lulzbuster(opts);
       __EXIT_SUCCESS;
       break;
     case 'H':
       usage();
       free_lulzbuster(opts);
       __EXIT_SUCCESS;
       break;
     default:
       free_lulzbuster(opts);
       err(E_ARGS);
    }
  }

  return;
}

