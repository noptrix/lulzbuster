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
* http.c                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <string.h>
#include <time.h>


/* own includes */
#include "http.h"
#include "wrapper.h"
#include "log.h"
#include "error.h"
#include "lulzbuster.h"


/* built-in user-agents list */
static useragents_T useragents[] = {
/*  {"android", "firefox", "Mozilla/5.0 (Android 9; Mobile; rv:72.0) Gecko/71.0 Firefox/72.0"},
  {"android", "firefox", "Mozilla/5.0 (Android 9; Mobile; rv:71.0) Gecko/71.0 Firefox/71.0"},
  {"android", "firefox", "Mozilla/5.0 (Android 8.0.0; Mobile; rv:68.4.1) Gecko/68.4.1 Firefox/68.4.1"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 8.0.0; SM-G930F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.101 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 10; ONEPLUS A6013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.116 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 8.0.0; moto e5 plus) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.116 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 8.0.0; SAMSUNG SM-G930F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/10.2 Chrome/71.0.3578.99 Mobile Safari/537.36"},
  {"android", "chrome", "Mozilla/5.0 (Linux; Android 9; Nokia 3.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.136 Mobile Safari/537.36"},
  {"android", "opera", "Mozilla/5.0 (Linux; Android 10; MAR-LX1A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.116 Mobile Safari/537.36 OPR/55.2.2719.50740"},
  {"android", "opera", "Mozilla/5.0 (Linux; Android 7.0; SM-A310F Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.91 Mobile Safari/537.36 OPR/42.7.2246.114996"},
  {"android", "samsung", "Mozilla/5.0 (Linux; Android 9; SAMSUNG SM-J730F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/10.2 Chrome/71.0.3578.99 Mobile Safari/537.36"},
  {"android", "samsung", "Mozilla/5.0 (Linux; Android 9; SAMSUNG SM-S102DL) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/10.2 Chrome/71.0.3578.99 Mobile Safari/537.36"},
  {"bot", "ahrefsbot", "Mozilla/5.0 (compatible; AhrefsBot/6.1; +http://ahrefs.com/robot/)"},
  {"bot", "bingbot", "Mozilla/5.0 (compatible; bingbot/2.0 +http://www.bing.com/bingbot.htm)"},
  {"bot", "baiduspider", "Baiduspider+(+http://www.baidu.com/search/spider.htm)"},
  {"bot", "googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
  {"bot", "msie", "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"},
  {"bot", "yahoo", "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)"},
  {"bot", "yandex", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"},
  {"ios", "safari", "Mozilla/5.0 (iPad; CPU OS 11_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Tablet/15E148 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPad; CPU OS 13_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/79.0.3945.73 Mobile/15E148 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 13_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/89.2.287201133 Mobile/15E148 Safari/604.1"},
  {"ios", "safari", "Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1"},
  {"ios", "firefox", "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) FxiOS/7.5b3349 Mobile/14F89 Safari/603.2.4"},
  {"ios", "chrome", "Mozilla/5.0 (iPhone; CPU iPhone OS 9_3_2 like Mac OS X) AppleWebKit/601.1 (KHTML, like Gecko) CriOS/51.0.2704.104 Mobile/13F69 Safari/601.1.46"},*/
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS aarch64 12607.58.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.86 Safari/537.36"},
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS x86_64 12239.19.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.38 Safari/537.36"},
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS armv7l 12371.89.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36"},
  {"chromiumos", "chrome", "Mozilla/5.0 (X11; CrOS x86_64 12607.82.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.123 Safari/537.36"},
  {"freebsd", "chrome", "Mozilla/5.0 (X11; FreeBSD amd64; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Iridium/2019.04 Safari/537.36 Chrome/73.0.0.0"},
  {"freebsd", "firefox", "Mozilla/5.0 (X11; FreeBSD amd64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Linux i686; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"linux", "firefox", "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"linux", "chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"linux", "crhome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4029.4 Safari/537.36"},
  {"linux", "opera", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36 OPR/62.0.3331.14 (Edition beta),gzip(gfe)"},
  {"linux", "vivaldi", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.134 Safari/537.36 Vivaldi/2.5.1525.40"},
  {"linux", "links", "Links (2.7; Linux 3.5.0-17-generic x86_64; GNU C 4.7.1; text)"},
  {"linux", "lynx", "Lynx/2.8.6rel.4 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/1.6.3"},
  {"linux", "midori", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15 Midori/6"},
  {"linux", "thunderbird", "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Thunderbird/68.4.1"},
  {"linux", "thunderbird", "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Thunderbird/68.4.1 Lightning/68.4.1"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.4 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.4 Safari/605.1.15"},
  {"macos", "safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/21.0 Safari/605.1.15"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"macos", "firefox", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:71.0) Gecko/20100101 Firefox/71.0"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.36 Safari/537.36"},
  {"macos", "chrome", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"macos", "opera", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36 OPR/66.0.3515.36"},
  {"macos", "opera", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36 OPR/60.0.3255.170"},
  {"openbsd", "chrome", "Mozilla/5.0 (X11; OpenBSD amd64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"},
  {"openbsd", "chrome", "Mozilla/5.0 (X11; OpenBSD amd64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.124 Safari/537.36"},
  {"openbsd", "firefox", "Mozilla/5.0 (X11; OpenBSD amd64; rv:71.0) Gecko/20100101 Firefox/71.0"},
  {"openbsd", "firefox", "Mozilla/5.0 (X11; OpenBSD amd64; rv:62.0) Gecko/20100101 Firefox/62.0"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Cortana 1.14.0.19041; 10.0.0.0.19041.21) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19041"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Cortana 1.13.0.18362; 10.0.0.0.18363.592) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18363"},
  {"windows", "edge", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:72.0) Gecko/20100101 Firefox/72.0"},
  {"windows", "firefox", "Mozilla/5.0 (Windows NT 6.4; WOW64; rv:71.0) Gecko/20100101 Firefox/71.0"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4034.0 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"},
  {"windows", "chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3835.0 Safari/537.36"},
  {"windows", "opera", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.27 Safari/537.36 OPR/62.0.3331.10 (Edition beta)"},
  {"windows", "opera", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36 OPR/64.0.3417.170"},
  {"windows", "opera", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36 OPR/65.0.3467.78"},
  {"windows", "vivaldi", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.94 Safari/537.36 Vivaldi/2.6.1566.40"},
};


/* pthread mutex locks */
static pthread_mutex_t locks[NUM_LOCKS];


/* generate a random url based on given url: base + /foo + randintstr + .txt */
static char *rand_url(const char *url)
{
  char *randurl = NULL;
  register int randno = 0;
  register size_t randurl_size = 0;

  srand(time(NULL));
  randno = rand();
  randurl_size = snprintf(NULL, 0, "%s/%d.txt", url, randno) + 1;
  randurl = xcalloc(1, randurl_size + 1);
  snprintf(randurl, randurl_size, "%s/%d.txt", url, randno);

  return randurl;
}


/* connection check and wildcard detection. if wildcard response detected save
 * the body size so we can use that later in attack() */
wildcard_T check_conn_wildcard(const char *url)
{
  static wildcard_T wcard;
  char *randurl = rand_url(url);
  CURL *curl = curl_easy_init();
  CURLcode res = 0;

  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, randurl);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, TCP_CONN_TIMEOUT);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_cb);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    res = curl_easy_perform(curl);
    free(randurl);
    if (res != CURLE_OK) {
      wcard.conn_ok = FALSE;
    } else {
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &wcard.resp_code);
      curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &wcard.resp_size);
      wcard.conn_ok = TRUE;
    }
  }

  curl_easy_cleanup(curl);

  return wcard;
}


/* parse a given url */
url_T parse_url(const char *url)
{
  static url_T parsed_url;
  CURLUcode rc = 0;
  CURLU *purl = curl_url();

  /* i know this is weird but for now it's enough if either of one fails to
   * thell then: ERR_URL_PARSE. just to save code lines :) if needed i can
   * change later for individual error handling. also, this would rarely happen
   * since we check for valid url before */
  rc = curl_url_set(purl, CURLUPART_URL, url, 0);
  rc = curl_url_get(purl, CURLUPART_SCHEME, &parsed_url.scheme, 0);
  rc = curl_url_get(purl, CURLUPART_HOST, &parsed_url.host, 0);
  rc = curl_url_get(purl, CURLUPART_PORT, &parsed_url.port, CURLU_DEFAULT_PORT);
  rc = curl_url_get(purl, CURLUPART_PATH, &parsed_url.path, 0);

  if (rc != CURLUE_OK) {
    free_parsed_url(parsed_url);
    err(E_URL_PARSE);
  }

  curl_url_cleanup(purl);

  return parsed_url;
}


/* randomly fetch an useragent from useragents tables */
const char *get_rand_useragent()
{
  register int size = ARRAY_SIZE(useragents);

  srand(time(NULL));

  return useragents[rand() / size % size].ua;
}


/* simply print built-in user-agent list (-A) */
void print_useragents()
{
  char *buff = NULL, *fmtstr = "%-10s | %-11s | %s\n";
  register size_t i = 0, len = 0, num_items = 0;

  num_items = ARRAY_SIZE(useragents);

  JSLOG("found %lu user-agents\n\n", num_items);
  SLOG("      %-12s %-13s %s\n\n", "OS", "Browser", "User-Agent");
  for (i = 0; i < num_items; ++i) {
    len = (strlen(useragents[i].os) + 1 + strlen(useragents[i].browser) + 1 + \
           strlen(useragents[i].ua) + 1) * sizeof(char *);
    len += snprintf(NULL, 0, fmtstr, useragents[i].os, useragents[i].browser,
                    useragents[i].ua) + 1;
    buff = xcalloc(1, len);
    snprintf(buff, len, fmtstr, useragents[i].os, useragents[i].browser,
             useragents[i].ua);
    VSLOG(buff);
    free(buff);
  }
  SLOG("\n");

  return;
}


/* do some necessary curl related cleanups */
unsigned char cleanup_http(curl_T *curl)
{
  curl_slist_free_all(curl->list);
  curl_share_cleanup(curl->sh);
  curl_easy_cleanup(curl->eh);
  curl_global_cleanup();

  return TRUE;
}


/* do some necessary curl related inits */
unsigned char init_http(curl_T *curl)
{
  register unsigned char check_ok = TRUE;

  /* curl global init */
  if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
    check_ok = FALSE;
  }

  /* initial handler init. will be duplicated for worker threads! */
  curl->eh = curl_easy_init();
  if (curl->eh == NULL) {
    check_ok = FALSE;
  }

  /* init shared object for easy handler */
  curl->sh = curl_share_init();
  if (curl->sh == NULL) {
    check_ok = FALSE;
  }

  if (check_ok == FALSE) {
    err(E_CURL_INIT);
    return check_ok;
  }

  /* init curl's linked list for our headers and other options we dyn. set. */
  curl->list = NULL;

  return check_ok;
}


/* unlock callback func for curl */
void unlock_cb(CURL *handle, curl_lock_data data, void *userptr)
{
  (void) handle;
  (void) userptr;

  pthread_mutex_unlock(&locks[data]);

  return;
}


/* lock callback func for curl */
void lock_cb(CURL *handle, curl_lock_data data, curl_lock_access access,
             void *userptr)
{
  (void) handle;
  (void) access;
  (void) userptr;

  pthread_mutex_lock(&locks[data]);

  return;
}


/* destroy initiated locks */
unsigned char kill_locks(void)
{
  register size_t i = 0;

  for (i = 0; i < NUM_LOCKS; ++i) {
    if (pthread_mutex_destroy(&locks[i]) != 0) {
      err(W_PTHR_MX_DSTR);
      return FALSE;
    }
  }

  return TRUE;
}


/* init pthread mutex locks */
unsigned char init_locks(void)
{
  register size_t i = 0;

  for (i = 0; i < NUM_LOCKS; ++i) {
    if (pthread_mutex_init(&locks[i], NULL) != 0) {
      err(E_PTHR_MX_INIT);
      return FALSE;
    }
  }

  return TRUE;
}


/* write callback func for curl */
size_t write_cb(void *buff, register size_t size, register size_t nmemb,
                void *userptr)
{
  (void) buff;
  (void) userptr;

  return size * nmemb; /* curl wants this otherwise we get '23' error code */
}


/* do http request for our attack worker thread */
unsigned char do_req(const char *url, CURL *handler, CURLSH *share)
{
  register unsigned char check_ok = TRUE;
  /*static unsigned char num_err = 0;
  CURLcode res = 0;*/

  /* set url and use shared object for our easy handlers */
  curl_easy_setopt(handler, CURLOPT_URL, url);
  curl_easy_setopt(handler, CURLOPT_SHARE, share);

  /* fire request. print error message in case something went wrong.
   * note: we could use CURLOPT_ERRORBUFFER here instead but the generic msg
   * from curl are enough.
   * TODO: be more pragmatic here and handle this correctly (stats, etc.) */
  curl_easy_perform(handler);
  /*res = curl_easy_perform(handler);
  switch (res) {
   case CURLE_OK:
     break;
   case CURLE_UNSUPPORTED_PROTOCOL:
   case CURLE_COULDNT_RESOLVE_PROXY:
   case CURLE_COULDNT_RESOLVE_HOST:
   case CURLE_REMOTE_ACCESS_DENIED:
   case CURLE_HTTP2:
   case CURLE_HTTP_RETURNED_ERROR:
   case CURLE_WRITE_ERROR:
   case CURLE_OPERATION_TIMEDOUT:
   case CURLE_HTTP_POST_ERROR:
   case CURLE_SSL_CONNECT_ERROR:
   case CURLE_TOO_MANY_REDIRECTS:
   case CURLE_SSL_ENGINE_NOTFOUND:
   case CURLE_SSL_ENGINE_SETFAILED:
   case CURLE_SEND_ERROR:
   case CURLE_RECV_ERROR:
   case CURLE_SSL_CERTPROBLEM:
   case CURLE_SSL_CIPHER:
   case CURLE_PEER_FAILED_VERIFICATION:
   case CURLE_BAD_CONTENT_ENCODING:
   case CURLE_FILESIZE_EXCEEDED:
   case CURLE_USE_SSL_FAILED:
   case CURLE_SEND_FAIL_REWIND:
   case CURLE_SSL_ENGINE_INITFAILED:
   case CURLE_LOGIN_DENIED:
   case CURLE_SSL_CACERT_BADFILE:
   case CURLE_AGAIN:
   case CURLE_SSL_CRL_BADFILE:
   case CURLE_SSL_ISSUER_ERROR:
   case CURLE_NO_CONNECTION_AVAILABLE:
   case CURLE_SSL_PINNEDPUBKEYNOTMATCH:
   case CURLE_HTTP2_STREAM:
#ifndef LAME
   case CURLE_AUTH_ERROR:
   case CURLE_HTTP3:
#endif
     if (num_err < MAX_CURL_ERRORS) {
       if (num_err == 0) {
         SLOG("\n");
       }
       WSLOG("curl error: %s\n", curl_easy_strerror(res));
       ++num_err;
     }
     break;
   default:
     if (num_err < MAX_CURL_ERRORS) {
       if (num_err == 0) {
         SLOG("\n")
       }
       WSLOG("unknown curl error: %s\n", curl_easy_strerror(res));
     }
  }
*/
  return check_ok;
}

