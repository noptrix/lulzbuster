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
#include "log.h"


/* set static http (curl) options. i wanted to refactor and make this dynamic
 * using a structure and for() to assign and call curl_easy_setopt(). problem
 * is that there are various data types needed. casting etc. here is NO-WAY. */
bool set_http_options(opts_T *opts)
{
  /* enable tcp fastopen */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_TCP_FASTOPEN, 1L) != CURLE_OK) {
    err(E_CURL_TCPFAST);
    return false;
  }

  /* set dns caching to remain forever (-1L per libcurl docs) */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_DNS_CACHE_TIMEOUT, -1L) != \
      CURLE_OK) {
    err(E_CURL_DNSCACHE);
    return false;
  }

  /* send curl data (http responses) to our write_cb() callback */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_WRITEFUNCTION, write_cb) != \
      CURLE_OK) {
    err(E_CURL_WF);
    return false;
  }

  /* max connect cache pool size */
  if (opts->conn_cache) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_MAXCONNECTS,
                         opts->conn_cache) != CURLE_OK) {
      err(E_CURL_MAXCONNS);
      return false;
    }
  }

  /* ssl/tls verification. default: full peer + host check. -i flips
   * both off (insecure mode). VERIFYHOST takes 2L for full host check
   * per curl docs - 1L is deprecated/removed */
  {
    long peer = opts->in_ssl ? 0L : 1L;
    long host = opts->in_ssl ? 0L : 2L;
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_SSL_VERIFYPEER, peer)
        != CURLE_OK) {
      err(E_CURL_SSL_PEER);
      return false;
    }
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_SSL_VERIFYHOST, host)
        != CURLE_OK) {
      err(E_CURL_SSL_HOST);
      return false;
    }
  }

  /* mTLS: client cert + key for servers that demand them. PEM only
   * (curl's default). passphrase is optional - only set when the key
   * is encrypted. each curl_easy_setopt failure is fatal because a
   * silent fallback would hand back a "connection ok" against an
   * mTLS-protected target with no auth, total false positive */
  if (opts->cert_file) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_SSLCERT,
                         opts->cert_file) != CURLE_OK) {
      err(E_CURL_SSLCERT);
      return false;
    }
  }
  if (opts->key_file) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_SSLKEY,
                         opts->key_file) != CURLE_OK) {
      err(E_CURL_SSLKEY);
      return false;
    }
  }
  if (opts->key_pass) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_KEYPASSWD,
                         opts->key_pass) != CURLE_OK) {
      err(E_CURL_KEYPASS);
      return false;
    }
  }

  /* user-agent */
  if (opts->useragent) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_USERAGENT,
                         opts->useragent) != CURLE_OK) {
      err(E_CURL_UAGENT);
      return false;
    }
  }

  /* http request method. no body read if http method "HEAD" was chosen,
   * otherwise too slow!  */
  if (opts->http_method) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_CUSTOMREQUEST,
                         opts->http_method) != CURLE_OK) {
      err(E_CURL_CREQUEST);
      return false;
    }
    if (strcmp(opts->http_method, "HEAD") == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_NOBODY, 1L) != CURLE_OK) {
        err(E_CURL_NOBODY);
        return false;
      }
    }
  }

  /* follow redirects. -F always honored when -f is on (incl. 0 = no
   * hops allowed). default -1 = unlimited (curl's own default), so
   * '-f' alone matches the historical behavior */
  if (opts->follow_redir) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_FOLLOWLOCATION, 1L)
        != CURLE_OK) {
      err(E_CURL_FOLLOW);
      return false;
    }
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_MAXREDIRS,
                         opts->follow_redir_level) != CURLE_OK) {
      err(E_CURL_MAXRDIRS);
      return false;
    }
  }

  /* auto referrer value update */
  if (curl_easy_setopt(opts->curl->eh, CURLOPT_AUTOREFERER,
                       opts->autoref ? 1L : 0L) != CURLE_OK) {
    err(E_CURL_AREFER);
    return false;
  }

  /* connection timeout */
  if (opts->conn_timeout) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_CONNECTTIMEOUT,
                         opts->conn_timeout) != CURLE_OK) {
      err(E_CURL_TIMEOUT);
      return false;
    }
  }

  /* request timeout */
  if (opts->req_timeout) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_TIMEOUT,
                         opts->req_timeout) != CURLE_OK) {
      err(E_CURL_TIMEOUT);
      return false;
    }
  }

  /* http auth: creds + http auth types to support */
  if (opts->creds) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_USERPWD, opts->creds) != \
        CURLE_OK) {
      err(E_CURL_USERPWD);
      return false;
    }
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTPAUTH, CURLAUTH_ANY) != \
        CURLE_OK) {
      err(E_CURL_HTTPAUTH);
      return false;
    }
  }

  /* disable the curl's default Accept header */
  opts->curl->list = curl_slist_append(opts->curl->list, "Accept:");
  if (opts->curl->list == NULL) {
    err(E_CURL_SLIST);
    return false;
  }

  /* set custom headers */
  if (opts->http_header) {
    opts->curl->list = curl_slist_append(opts->curl->list, opts->http_header);
    if (opts->curl->list == NULL) {
      err(E_CURL_SLIST);
      return false;
    }
  }

  /* enable custom headers */
  if (opts->curl->list) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTPHEADER,
                         opts->curl->list) != CURLE_OK) {
      err(E_CURL_HTTPHDR);
      return false;
    }
  }

  /* proxy shit */
  if (opts->proxy) {
    if (curl_easy_setopt(opts->curl->eh, CURLOPT_PROXY, opts->proxy) != \
        CURLE_OK) {
      err(E_CURL_PROXY);
      return false;
    }
    if (opts->proxy_creds) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_PROXYAUTH, CURLAUTH_ANY) != \
          CURLE_OK) {
        err(E_CURL_PAUTH);
        return false;
      }
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_PROXYUSERPWD,
                           opts->proxy_creds) != CURLE_OK) {
        err(E_CURL_PCREDS);
        return false;
      }
    }
  }

  /* http version */
  if (opts->http_version) {
    if (strcmp(opts->http_version, HTTP_VER_10) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_1_0) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return false;
      }
    }
    if (strcmp(opts->http_version, HTTP_VER_11) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_1_1) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return false;
      }
    }
    if (strcmp(opts->http_version, HTTP_VER_20) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_2) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return false;
      }
    }
#ifndef LAME
    if (strcmp(opts->http_version, HTTP_VER_30) == 0) {
      if (curl_easy_setopt(opts->curl->eh, CURLOPT_HTTP_VERSION,
                           CURL_HTTP_VERSION_3) != CURLE_OK) {
        err(E_CURL_HTTPVER);
        return false;
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
    return false;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_SHARE,
                        CURL_LOCK_DATA_SSL_SESSION) != CURLSHE_OK) {
    err(E_CURLSH_SSL);
    return false;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_SHARE,
                        CURL_LOCK_DATA_CONNECT) != CURLSHE_OK) {
    err(E_CURLSH_CONN);
    return false;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_LOCKFUNC, lock_cb) != \
      CURLSHE_OK) {
    err(E_CURLSH_LF);
    return false;
  }
  if (curl_share_setopt(opts->curl->sh, CURLSHOPT_UNLOCKFUNC, unlock_cb) != \
      CURLSHE_OK) {
    err(E_CURLSH_ULF);
    return false;
  }

  return true;
}


/* dump final-settings block to stderr. mirrors the layout of the old
 * __PRINT_OPTS macro - one line per relevant opt, indented with the
 * "    > " prefix. only fields the user actually set get a line so
 * the block stays compact (e.g. no proxy line when -p wasn't given).
 * pure output sink, no side effects beyond stderr writes */
void print_opts(const opts_T *opts)
{
  size_t i = 0;
  char **tptr = NULL;

  CLOG(stderr, "\n");
  JSLOG("final settings\n\n");

  fprintf(stderr, "    > url:          %s\n", opts->start_url);
  fprintf(stderr, "    > http method:  %s\n", opts->http_method);

  fprintf(stderr, "    > http excodes: ");
  for (i = 0; opts->http_ex_codes[i] != 0; ++i) {
    fprintf(stderr, "%ld ", opts->http_ex_codes[i]);
  }
  fprintf(stderr, "\n");

  fprintf(stderr, "    > follow redir: %d\n", (int) opts->follow_redir);
  if (opts->follow_redir) {
    if (opts->follow_redir_level < 0) {
      fprintf(stderr, "    > redir level:  unlimited\n");
    } else {
      fprintf(stderr, "    > redir level:  %ld\n", opts->follow_redir_level);
    }
  }

  if (opts->rand_ua) {
    fprintf(stderr, "    > random ua:    %d\n", (int) opts->rand_ua);
  } else {
    fprintf(stderr, "    > ua:           %s\n", opts->useragent);
  }

  if (opts->http_header) {
    fprintf(stderr, "    > http header:  %s\n", opts->http_header);
  }
  if (opts->creds) {
    fprintf(stderr, "    > creds:        %s\n", opts->creds);
  }
  if (opts->http_version) {
    fprintf(stderr, "    > http version: %s\n", opts->http_version);
  }
  if (opts->min_resp_size > 0) {
    fprintf(stderr, "    > min size:     %lldB\n", opts->min_resp_size);
  }
  if (opts->max_resp_size > 0) {
    fprintf(stderr, "    > max size:     %lldB\n", opts->max_resp_size);
  }
  if (opts->body_match_set) {
    fprintf(stderr, "    > body match:   %s\n", opts->body_match);
  }
  if (opts->body_exclude_set) {
    fprintf(stderr, "    > body exclude: %s\n", opts->body_exclude);
  }
  if (opts->autoref) {
    fprintf(stderr, "    > auto referer: on\n");
  }
  if (opts->in_ssl) {
    fprintf(stderr, "    > insecure ssl: on\n");
  }
  if (opts->cert_file) {
    fprintf(stderr, "    > client cert: %s\n", opts->cert_file);
  }
  if (opts->key_file) {
    fprintf(stderr, "    > client key:  %s\n", opts->key_file);
  }
  if (opts->key_pass) {
    fprintf(stderr, "    > key pass:    (set)\n");
  }
  if (opts->delay != OFF) {
    fprintf(stderr, "    > delay:        %us\n", opts->delay);
  }

  fprintf(stderr, "    > con timeout:  %lds\n", opts->conn_timeout);
  fprintf(stderr, "    > req timeout:  %lds\n", opts->req_timeout);
  if (opts->glob_timeout != OFF) {
    fprintf(stderr, "    > glb timeout:  %us\n", opts->glob_timeout);
  }

  fprintf(stderr, "    > threads:      %u\n", opts->threads);
  fprintf(stderr, "    > con cache:    %ld\n", opts->conn_cache);
  fprintf(stderr, "    > wordlist:     %s\n", opts->wordlist);

  /* skip the synthetic "" entry that set_extensions() always inserts.
   * only print the user-given extensions; if the user gave none the
   * list is just [""] so we print nothing here */
  if (opts->extens != NULL) {
    bool any = false;
    for (tptr = opts->extens; *tptr != NULL; ++tptr) {
      if ((*tptr)[0] != '\0') { any = true; break; }
    }
    if (any) {
      fprintf(stderr, "    > extensions:   ");
      for (tptr = opts->extens; *tptr != NULL; ++tptr) {
        if ((*tptr)[0] != '\0') fprintf(stderr, "%s ", *tptr);
      }
      fprintf(stderr, "\n");
    }
  }

  if (opts->proxy) {
    fprintf(stderr, "    > proxy:        %s\n", opts->proxy);
  }
  if (opts->proxy_creds) {
    fprintf(stderr, "    > proxy creds:  %s\n", opts->proxy_creds);
  }

  fprintf(stderr, "    > dns server:   %s\n", opts->nameserver);

  if (opts->log_formats == 0) {
    fprintf(stderr, "    > logfile:      stderr only\n");
  } else {
    if (opts->log_paths[LOG_FMT_TEXT]) {
      fprintf(stderr, "    > log:          %s\n",
              opts->log_paths[LOG_FMT_TEXT]);
    }
    if (opts->log_paths[LOG_FMT_CSV]) {
      fprintf(stderr, "    > csv:          %s\n",
              opts->log_paths[LOG_FMT_CSV]);
    }
    if (opts->log_paths[LOG_FMT_JSONL]) {
      fprintf(stderr, "    > jsonl:        %s\n",
              opts->log_paths[LOG_FMT_JSONL]);
    }
  }

  fprintf(stderr, "    > smart mode:   %d\n", (int) opts->smart);
  if (opts->smart) {
    fprintf(stderr, "    > clst thresh:  %u\n", opts->cluster_threshold);
  }

  fprintf(stderr, "    > recurse:      %u\n", opts->recurse_depth);

  if (opts->exclude_paths != NULL && opts->num_exclude_paths > 0) {
    fprintf(stderr, "    > excludes:     ");
    for (i = 0; i < opts->num_exclude_paths; ++i) {
      fprintf(stderr, "%s ", opts->exclude_paths[i]);
    }
    fprintf(stderr, "\n");
  }

  fprintf(stderr, "\n");
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
  }

  /* fallback when no -A or when -A '' / -A ',' produced an empty list
   * via strtok. without this we'd build 0 attack urls and silently
   * scan nothing. inserting "" makes the build_urls loop emit one
   * bare <url>/<word> per word, matching the no-A behavior. allocate
   * 2 slots so the trailing NULL terminator the rest of the codebase
   * relies on is present */
  if (opts->extens == NULL || opts->num_extens == 0) {
    free(opts->extens); /* free()ing NULL is a no-op */
    opts->extens = xcalloc(2, sizeof(char *));
    opts->extens[0] = "";
    opts->extens[1] = NULL;
    opts->num_extens = 1;
  } else {
    /* "-A appends": always probe the bare word in addition to the
     * user's extensions. matches the help text's wording and matches
     * what users coming from gobuster/ffuf/dirb expect. we insert ""
     * at index 0 so bare hits show up first per word. realloc to
     * num+2 (+1 for the "", +1 for the NULL terminator parse_str_token
     * already wrote). the prepended slot must mirror the rest of the
     * list's ownership: heap-strdup when entries are heap-owned (session
     * load), otherwise a string literal (cmdline -A holds argv pointers).
     * keeping ownership uniform lets free_lulzbuster's loop deep-free
     * the whole array without a special case */
    bool has_bare = false;
    for (i = 0; i < opts->num_extens; ++i) {
      if (opts->extens[i][0] == '\0') { has_bare = true; break; }
    }
    if (!has_bare) {
      char *bare = "";
      if (opts->own_extens) {
        bare = xcalloc(1, 1); /* "\0" - heap-owned empty string */
      }
      opts->extens = xrealloc(opts->extens,
                              (opts->num_extens + 2) * sizeof(char *));
      memmove(&opts->extens[1], &opts->extens[0],
              (opts->num_extens + 1) * sizeof(char *));
      opts->extens[0] = bare;
      opts->num_extens++;
    }
  }

  /* count exclude paths so workers don't have to scan-to-NULL each time */
  if (opts->exclude_paths != NULL) {
    for (i = 0, tptr = opts->exclude_paths; *tptr != NULL; ++tptr, ++i);
    opts->num_exclude_paths = i;
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

  /* read_lines returns NULL on fopen() failure (e.g. wordlist got
   * deleted between check_file() and now). without this guard the
   * tmpwords[0] deref below would crash. free(NULL) is safe */
  if (tmpwords == NULL || tmpwords[0] == NULL) {
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
  opts->smart = false;
  opts->cluster_threshold = DEF_CLUSTER_THRESHOLD;
  opts->recurse_depth = DEF_RECURSE_DEPTH;
  opts->nameserver = DEF_NAMESERVER;

  return;
}


/* parse command line opts and run misc routines */
void parse_opts(int argc, char *argv[], opts_T *opts)
{
  int c = 0;
  opterr = 0;         /* STFU while errors occur within getopt() */

  while ((c = getopt(argc, argv,
    "s:h:x:fF:u:Uc:a:rj:D:C:R:T:t:g:w:A:p:P:iE:y:Y:SK:d:e:n:l:z:m:M:O:b:B:NXVH"))
         != -1) {
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
       opts->follow_redir = true;
       break;
     case 'F':
       opts->follow_redir_level = ATOI(optarg);
       break;
     case 'u':
       opts->useragent = optarg;
       break;
     case 'U':
       opts->rand_ua = true;
       break;
     case 'c':
       opts->http_header = optarg;
       break;
     case 'a':
       opts->creds = optarg;
       break;
     case 'r':
       opts->autoref = true;
       break;
     case 'j':
       opts->http_version = optarg;
       break;
     case 'D':
       opts->delay = (unsigned int) ATOI(optarg);
       break;
     case 'C':
       opts->conn_timeout = ATOI(optarg);
       break;
     case 'R':
       opts->req_timeout = ATOI(optarg);
       break;
     case 'T': {
       /* clamp to ushort range so values >65535 don't silently wrap */
       long t = ATOI(optarg);
       if (t < 0) t = 0;
       if (t > 65535) t = 65535;
       opts->glob_timeout = (unsigned short int) t;
       break;
     }
     case 't': {
       /* cap at MAX_THRDS so absurd values don't melt the box. the
        * downstream check_num() also warns on >MAX_THRDS but only after
        * the value was already truncated mod 65536, so do it here */
       long t = ATOI(optarg);
       if (t < 1) t = 1;
       if (t > MAX_THRDS) {
         err(W_THRDS);
         t = MAX_THRDS;
       }
       opts->threads = (unsigned short int) t;
       break;
     }
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
       opts->in_ssl = true;
       break;
     case 'E':
       opts->cert_file = optarg;
       break;
     case 'y':
       opts->key_file = optarg;
       break;
     case 'Y':
       opts->key_pass = optarg;
       break;
     case 'S':
       opts->smart = true;
       break;
     case 'K': {
       long t = ATOI(optarg);
       if (t < MIN_CLUSTER_THRESHOLD) t = MIN_CLUSTER_THRESHOLD;
       if (t > MAX_CLUSTER_THRESHOLD) t = MAX_CLUSTER_THRESHOLD;
       opts->cluster_threshold = (unsigned short int) t;
       break;
     }
     case 'd': {
       long t = ATOI(optarg);
       if (t < 0) t = 0;
       if (t > MAX_RECURSE_DEPTH) t = MAX_RECURSE_DEPTH;
       opts->recurse_depth = (unsigned short int) t;
       break;
     }
     case 'e':
       opts->exclude_paths = parse_str_token(optarg, ",", MAX_EX_PATHS);
       break;
     case 'n':
       opts->nameserver = optarg;
       break;
     case 'l':
       opts->logfile = optarg;
       break;
     case 'z':
       opts->resume_file = optarg;
       break;
     case 'm': {
       long long s = parse_size(optarg);
       if (s < 0) {
         err(E_SIZE);
       }
       opts->min_resp_size = s;
       break;
     }
     case 'M': {
       long long s = parse_size(optarg);
       if (s < 0) {
         err(E_SIZE);
       }
       opts->max_resp_size = s;
       break;
     }
     case 'b': {
       /* compile match regex once. POSIX extended (REG_EXTENDED) so users
        * can write 'admin|login' without escaping. REG_NOSUB - we don't
        * care about capture groups, just success/fail */
       int rc = regcomp(&opts->body_match_re, optarg,
                        REG_EXTENDED | REG_NOSUB);
       if (rc != 0) {
         err(E_REGEX);
       }
       opts->body_match = optarg;
       opts->body_match_set = true;
       break;
     }
     case 'B': {
       int rc = regcomp(&opts->body_exclude_re, optarg,
                        REG_EXTENDED | REG_NOSUB);
       if (rc != 0) {
         err(E_REGEX);
       }
       opts->body_exclude = optarg;
       opts->body_exclude_set = true;
       break;
     }
     case 'O': {
       /* parse comma-separated format list. accepts 'all' as alias for
        * log,csv,jsonl. each named token sets a bit in log_formats so
        * the rest of the pipeline can iterate over selected formats */
       char *dup = NULL, *tok = NULL, *save = NULL;
       size_t alen = strlen(optarg);
       if (alen == 0) err(E_FMT);
       dup = xcalloc(1, alen + 1);
       memcpy(dup, optarg, alen);
       for (tok = strtok_r(dup, ",", &save); tok != NULL;
            tok = strtok_r(NULL, ",", &save)) {
         if      (strcmp(tok, "log")   == 0) opts->log_formats |= LOG_FMT_BIT_TEXT;
         else if (strcmp(tok, "csv")   == 0) opts->log_formats |= LOG_FMT_BIT_CSV;
         else if (strcmp(tok, "jsonl") == 0) opts->log_formats |= LOG_FMT_BIT_JSONL;
         else if (strcmp(tok, "all")   == 0) opts->log_formats |= LOG_FMT_BIT_ALL;
         else { free(dup); err(E_FMT); }
       }
       free(dup);
       if (opts->log_formats == 0) err(E_FMT); /* e.g. "-O ," */
       break;
     }
     case 'N':
       opts->no_color = true;
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

