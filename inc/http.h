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
* HTTP.h                                                                       *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef HTTP_H
#define HTTP_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <curl/curl.h>
#include <pthread.h>
#include <stdbool.h>


/* own includes */


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* available HTTP request methods */
#define HTTP_HEAD     "HEAD"
#define HTTP_GET      "GET"
#define HTTP_POST     "POST"
#define HTTP_PUT      "PUT"
#define HTTP_DELETE   "DELETE"
#define HTTP_OPTIONS  "OPTIONS"

/* available HTTP versions */
#define HTTP_VER_10 "1.0"
#define HTTP_VER_11 "1.1"
#define HTTP_VER_20 "2.0"
#define HTTP_VER_30 "3.0"

/* http codes */
#define HTTP_ZERO                           0
#define HTTP_CONTINUE                       100
#define HTTP_SWITCHING_PROTOCOLS            101
#define HTTP_OK                             200
#define HTTP_CREATED                        201
#define HTTP_ACCEPTED                       202
#define HTTP_NON_AUTHORITATIVE              203
#define HTTP_NO_CONTENT                     204
#define HTTP_RESET_CONTENT                  205
#define HTTP_PARTIAL_CONTENT                206
#define HTTP_MULTIPLE_CHOICES               300
#define HTTP_MOVED_PERMANENTLY              301
#define HTTP_MOVED_TEMPORARILY              302
#define HTTP_SEE_OTHER                      303
#define HTTP_NOT_MODIFIED                   304
#define HTTP_USE_PROXY                      305
#define HTTP_BAD_REQUEST                    400
#define HTTP_UNAUTHORIZED                   401
#define HTTP_PAYMENT_REQUIRED               402
#define HTTP_FORBIDDEN                      403
#define HTTP_NOT_FOUND                      404
#define HTTP_METHOD_NOT_ALLOWED             405
#define HTTP_NOT_ACCEPTABLE                 406
#define HTTP_PROXY_AUTHENTICATION_REQUIRED  407
#define HTTP_REQUEST_TIME_OUT               408
#define HTTP_CONFLICT                       409
#define HTTP_GONE                           410
#define HTTP_LENGTH_REQUIRED                411
#define HTTP_PRECONDITION_FAILED            412
#define HTTP_REQUEST_ENTITY_TOO_LARGE       413
#define HTTP_REQUEST_URI_TOO_LARGE          414
#define HTTP_UNSUPPORTED_MEDIA_TYPE         415
#define HTTP_INTERNAL_SERVER_ERROR          500
#define HTTP_NOT_IMPLEMENTED                501
#define HTTP_BAD_GATEWAY                    502
#define HTTP_SERVICE_UNAVAILABLE            503
#define HTTP_GATEWAY_TIME_OUT               504
#define HTTP_VERSION_NOT_SUPPORTED          505
#define HTTP_VARIANT_ALSO_VARIES            506

/* max len for http method */
#define MAX_METHOD_LEN 24

/* max status codes to exclude. note: i use IANAs default list and removed the
 * unassigned ones from
 * http://www.iana.org/assignments/http-status-codes/http-status-codes-1.csv
 * which gives us 62 codes. i add 2 on top of it since i am polite. */
#define MAX_HTTP_STATUS_CODES 62 + 2

/* max exclude dirs. i assume that no one is going to define more than this on
 * the cmdline. i know this is dirty. will be changed in the future (refer to
 * parse_str_token()). */
#define MAX_EX_DIRS 64 + 1

/* max extensions list. we should be fine with 16 max */
#define MAX_EXTENSIONS  16 + 1

/* available proxy schemes */
#define PROXY_SCHEME_HTTP     "http"
#define PROXY_SCHEME_HTTPS    "https"
#define PROXY_SCHEME_SOCKS4   "socks4"
#define PROXY_SCHEME_SOCKS4A  "socks4a"
#define PROXY_SCHEME_SOCKS5   "socks5"
#define PROXY_SCHEME_SOCKS5H  "socks5h"

/* pthread mutex locks num */
#define NUM_LOCKS CURL_LOCK_DATA_LAST

/* max curl error we want to print during attack */
#define MAX_CURL_ERRORS 5

/*******************************************************************************
 * VARS
 ******************************************************************************/


/* curl table */
typedef struct {
  CURL *eh;                 /* curl easy handler */
  CURLSH *sh;               /* curl share object for easy handler */
  struct curl_slist *list;  /* curl's linked list (for our headers etc.) */
  CURLcode curl_res;        /* curl result code*/
} curl_T;

/* useragents table */
typedef struct {
  const char *os;
  const char *browser;
  const char *ua;
} useragents_T;

/* upper bound on the per-request body buffer used for -b/-B regex
 * matching. anything past this gets truncated - matters for hits that
 * legitimately serve large bodies (binary downloads etc), but the
 * signal we care about (page titles, error strings, "login" markers)
 * lives in the first few KB. 1 MiB is the sweet spot for our 30-thread
 * default before memory pressure starts to bite */
#define BODY_CAPTURE_MAX  (1024 * 1024)

/* per-request body stats. one of these is stack-allocated in the attack
 * worker and passed via CURLOPT_WRITEDATA so write_cb can tally
 * bytes/lines/words while curl streams the body. when -b/-B is active
 * `buf` points to a heap-allocated capture region the worker owns; the
 * write_cb appends into it up to BODY_CAPTURE_MAX. NULL when regex
 * filters are off so we don't pay the memcpy/alloc cost */
typedef struct {
  size_t bytes;
  size_t lines;
  size_t words;
  bool in_word;
  char *buf;          /* body capture (NULL when no regex filter) */
  size_t buf_len;     /* current bytes in buf */
  size_t buf_cap;     /* capacity of buf (== BODY_CAPTURE_MAX when set) */
} body_stats_T;

/* parsed url table */
typedef struct {
  char *scheme;
  char *host;
  char *port;
  char *path;
  char *user;
  char *pass;
  char *query;
} url_T;

/* max num wildcard probes we fire at the target during startup. each
 * probe uses a different random URL shape so we can fingerprint sites
 * that respond differently per pattern */
#define MAX_WCARD_PROBES 5

/* one wildcard fingerprint = (response code, body size) tuple */
typedef struct {
  long resp_code;
  curl_off_t resp_size;
} wcard_fp_T;

/* for wildcard check */
typedef struct {
  wcard_fp_T fps[MAX_WCARD_PROBES];   /* unique (code, size) tuples */
  size_t num_fps;                     /* how many fps slots are filled */
  bool conn_ok;
  bool any_http_ok;                   /* any probe returned HTTP 200 */
} wildcard_T;


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* init stuff */
bool cleanup_http(curl_T *);
bool init_http(curl_T *);

/* print built-in user-agent list (-A) */
void print_useragents();

/* callbacks for curl */
void unlock_cb(CURL *, curl_lock_data, void *);
void lock_cb(CURL *, curl_lock_data, curl_lock_access, void *);
size_t write_cb(void *, size_t, size_t, void *);

/* pthread init and destroy locks */
bool kill_locks(void);
bool init_locks(void);

/* do http request for our attack worker thread */
bool do_req(const char *, CURL *, CURLSH *);

/* randomly fetch an useragent from useragents table */
const char *get_rand_useragent();

/* parse given url */
url_T parse_url(const char *);

/* connection check and wildcard detection. proxy + proxy_creds are
 * applied to the probe handle if non-NULL so the check goes thru the
 * same path as the real scan workers. in_ssl mirrors opts->in_ssl
 * so probe handles honor -i (insecure mode) like the workers do.
 * cert/key/key_pass enable mTLS on probes (else mTLS-protected
 * targets would 403 every probe and the scan would never start).
 * conn_timeout mirrors opts->conn_timeout (-C) so probes don't hang
 * 5x the user-set timeout against unreachable hosts */
wildcard_T check_conn_wildcard(const char *, const char *, const char *,
                               bool, const char *, const char *,
                               const char *, long);


#endif

