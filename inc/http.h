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

/* for wildcard check */
typedef struct {
  long resp_code;
  curl_off_t resp_size;
  unsigned char conn_ok;
} wildcard_T;


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* init stuff */
unsigned char cleanup_http(curl_T *);
unsigned char init_http(curl_T *);

/* print built-in user-agent list (-A) */
void print_useragents();

/* callbacks for curl */
void unlock_cb(CURL *, curl_lock_data, void *);
void lock_cb(CURL *, curl_lock_data, curl_lock_access, void *);
size_t write_cb(void *, size_t, size_t, void *);

/* pthread init and destroy locks */
unsigned char kill_locks(void);
unsigned char init_locks(void);

/* do http request for our attack worker thread */
unsigned char do_req(const char *, CURL *, CURLSH *);

/* randomly fetch an useragent from useragents table */
const char *get_rand_useragent();

/* parse given url */
url_T parse_url(const char *);

/* connection check and wildcard detection */
wildcard_T check_conn_wildcard(const char *);


#endif

