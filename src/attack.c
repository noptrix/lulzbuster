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
* attack.c                                                                     *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>


/* own includes */
#include "attack.h"
#include "log.h"
#include "wrapper.h"
#include "thpool.h"
#include "error.h"
#include "lulzbuster.h"
#include "misc.h"
#include "signals.h"
#include "session.h"


/* runtime cluster detection for smart mode. groups hits by
 * (code, size_bucket) and once a cluster crosses the threshold we stop
 * printing further hits in that cluster (probably wildcard noise).
 * threshold is configurable via -K, default DEF_CLUSTER_THRESHOLD */
#define HIT_BUCKET_SIZE          32
#define HIT_TABLE_INIT_CAP       64

typedef struct {
  long code;
  size_t size_bucket;
  size_t count;
  bool suppressed;
} hit_cluster_T;

struct hit_table {
  hit_cluster_T *clusters;
  size_t num_clusters;
  size_t cap;
  size_t threshold;
  pthread_mutex_t mtx;
};

/* decisions returned by hit_table_check */
#define HC_PRINT      0   /* print hit normally */
#define HC_SUPPRESSED 1   /* cluster already suppressed, skip */
#define HC_TRIGGER    2   /* this hit just triggered suppression */


/* end-of-scan stats. all counters updated by workers via atomic add,
 * timing recorded by main thread around launch_attack. process-scoped,
 * we only run one scan per invocation */
static unsigned long g_total_bytes = 0;
static unsigned long g_total_lines = 0;
static unsigned long g_total_words = 0;
static unsigned long g_total_hits  = 0;
static unsigned long g_codes[6]    = {0};   /* 0=other, 1..5=1xx..5xx */
static struct timespec g_t_start, g_t_end;


/* recursion: queue of directory urls workers want to recurse into. fed
 * by attack() workers under mutex, drained by launch_attack between
 * scan levels. only active when -d > 0 */
typedef struct {
  char **urls;
  size_t count;
  size_t cap;
  pthread_mutex_t mtx;
} dir_queue_T;

#define DIR_QUEUE_INIT_CAP  16

static dir_queue_T g_dirs;
static unsigned short int g_cur_level = 0;   /* 0 = initial, >=1 = recursing */

/* shared progress counter across workers - hoisted to file scope so
 * we can reset it between recursion levels via __atomic_store_n */
static size_t g_curjob = 0;


/* recursion candidate http codes - dirs that look 'real' and worth diving
 * into. 200 = ok, 301/302 = redirect (often slash-add), 401/403 =
 * existing but auth/perms */
static bool is_recursable(long code)
{
  return code == 200 || code == 301 || code == 302 ||
         code == 401 || code == 403;
}


/* substring exclude match against opts->exclude_paths. empty list = no
 * filter. case-sensitive, "logout" matches "/api/logout/" too */
static bool path_excluded(const char *url, opts_T *opts)
{
  size_t i = 0;

  if (opts->exclude_paths == NULL || opts->num_exclude_paths == 0) {
    return false;
  }
  for (i = 0; i < opts->num_exclude_paths; ++i) {
    if (opts->exclude_paths[i] != NULL &&
        opts->exclude_paths[i][0] != '\0' &&
        strstr(url, opts->exclude_paths[i]) != NULL) {
      return true;
    }
  }
  return false;
}


static bool dir_queue_init(dir_queue_T *q)
{
  q->urls = xcalloc(DIR_QUEUE_INIT_CAP, sizeof(char *));
  q->count = 0;
  q->cap = DIR_QUEUE_INIT_CAP;
  if (pthread_mutex_init(&q->mtx, NULL) != 0) {
    free(q->urls);
    q->urls = NULL;
    return false;
  }
  return true;
}


static void dir_queue_destroy(dir_queue_T *q)
{
  size_t i = 0;
  pthread_mutex_destroy(&q->mtx);
  if (q->urls != NULL) {
    for (i = 0; i < q->count; ++i) {
      free(q->urls[i]);
    }
    free(q->urls);
  }
  q->urls = NULL;
  q->count = 0;
  q->cap = 0;
}


/* take ownership of (a strdup of) url. dedup linear scan - level dirs
 * are rarely huge so it's fine. returns true on add, false on dup/oom */
static bool dir_queue_add(dir_queue_T *q, const char *url)
{
  size_t i = 0;
  bool added = false;
  char *copy = NULL;

  pthread_mutex_lock(&q->mtx);

  for (i = 0; i < q->count; ++i) {
    if (strcmp(q->urls[i], url) == 0) {
      goto out;
    }
  }
  if (q->count >= q->cap) {
    q->cap *= 2;
    q->urls = xrealloc(q->urls, q->cap * sizeof(char *));
  }
  copy = xcalloc(1, strlen(url) + 1);
  strcpy(copy, url);
  q->urls[q->count++] = copy;
  added = true;

out:
  pthread_mutex_unlock(&q->mtx);
  return added;
}


/* hand off the urls array; queue is reset to empty (cap kept). caller
 * owns *out_urls and the strings; must free both */
static void dir_queue_drain(dir_queue_T *q, char ***out_urls,
                            size_t *out_count)
{
  pthread_mutex_lock(&q->mtx);
  *out_urls = q->urls;
  *out_count = q->count;
  q->urls = xcalloc(DIR_QUEUE_INIT_CAP, sizeof(char *));
  q->count = 0;
  q->cap = DIR_QUEUE_INIT_CAP;
  pthread_mutex_unlock(&q->mtx);
}


/* static function prototypes */
static void *attack(job_T *);
static bool hit_table_init(struct hit_table *t, size_t threshold);
static void hit_table_destroy(struct hit_table *t);
static int hit_table_check(struct hit_table *t, long code, curl_off_t size,
                           size_t *out_bucket);
static void hit_table_summary(struct hit_table *t);
static void humanize_bytes(unsigned long n, char *buf, size_t bufsz);
static void scan_stats_summary(unsigned long num_requests);


static bool hit_table_init(struct hit_table *t, size_t threshold)
{
  t->clusters = xcalloc(HIT_TABLE_INIT_CAP, sizeof(hit_cluster_T));
  t->num_clusters = 0;
  t->cap = HIT_TABLE_INIT_CAP;
  t->threshold = threshold;
  if (pthread_mutex_init(&t->mtx, NULL) != 0) {
    free(t->clusters);
    return false;
  }
  return true;
}


static void hit_table_destroy(struct hit_table *t)
{
  pthread_mutex_destroy(&t->mtx);
  free(t->clusters);
  t->clusters = NULL;
  t->num_clusters = 0;
  t->cap = 0;
}


/* clear cluster bookkeeping between recursion levels. each new target
 * has its own response patterns so old (code, size_bucket) tallies
 * shouldn't bleed across */
static void hit_table_reset(struct hit_table *t)
{
  pthread_mutex_lock(&t->mtx);
  t->num_clusters = 0;
  pthread_mutex_unlock(&t->mtx);
}


/* lookup or insert (code, bucket), bump count, return decision */
static int hit_table_check(struct hit_table *t, long code, curl_off_t size,
                           size_t *out_bucket)
{
  size_t bucket = (size_t)(size / HIT_BUCKET_SIZE);
  hit_cluster_T *c = NULL;
  size_t i = 0;
  int decision = HC_PRINT;

  if (out_bucket) {
    *out_bucket = bucket;
  }

  pthread_mutex_lock(&t->mtx);

  for (i = 0; i < t->num_clusters; ++i) {
    if (t->clusters[i].code == code &&
        t->clusters[i].size_bucket == bucket) {
      c = &t->clusters[i];
      break;
    }
  }

  if (c == NULL) {
    if (t->num_clusters >= t->cap) {
      t->cap *= 2;
      t->clusters = xrealloc(t->clusters, t->cap * sizeof(hit_cluster_T));
    }
    c = &t->clusters[t->num_clusters++];
    c->code = code;
    c->size_bucket = bucket;
    c->count = 0;
    c->suppressed = false;
  }

  c->count++;

  if (c->suppressed) {
    decision = HC_SUPPRESSED;
  } else if (c->count >= t->threshold) {
    c->suppressed = true;
    decision = HC_TRIGGER;
  }

  pthread_mutex_unlock(&t->mtx);
  return decision;
}


/* dump end-of-scan summary for smart mode */
static void hit_table_summary(struct hit_table *t)
{
  size_t i = 0, printed = 0, suppressed = 0, sup_clusters = 0;
  hit_cluster_T *c = NULL;

  for (i = 0; i < t->num_clusters; ++i) {
    c = &t->clusters[i];
    if (c->suppressed) {
      sup_clusters++;
      printed += t->threshold - 1;
      suppressed += c->count - (t->threshold - 1);
    } else {
      printed += c->count;
    }
  }

  JSLOG("smart mode: %lu hits printed, %lu suppressed in %lu cluster(s)\n",
        printed, suppressed, sup_clusters);
}


/* helper: format byte count as human-readable like "1.2M" or "456k" */
static void humanize_bytes(unsigned long n, char *buf, size_t bufsz)
{
  if (n >= 1073741824UL) {
    snprintf(buf, bufsz, "%.2fG", (double) n / 1073741824.0);
  } else if (n >= 1048576UL) {
    snprintf(buf, bufsz, "%.2fM", (double) n / 1048576.0);
  } else if (n >= 1024UL) {
    snprintf(buf, bufsz, "%.2fK", (double) n / 1024.0);
  } else {
    snprintf(buf, bufsz, "%luB", n);
  }
}


/* dump end-of-scan summary: timing, throughput, body totals, code
 * breakdown and hit count. shown unconditionally, regardless of -S */
static void scan_stats_summary(unsigned long num_requests)
{
  double dur = (double)(g_t_end.tv_sec - g_t_start.tv_sec) +
               (double)(g_t_end.tv_nsec - g_t_start.tv_nsec) / 1e9;
  double rps = (dur > 0.0) ? ((double) num_requests / dur) : 0.0;
  char hbuf[32];

  if (dur < 0) dur = 0;

  /* match the 'final settings' block at startup: leading newline so the
   * stats are their own block, blank line after the header, and a
   * trailing newline after the last item */
  CLOG(stderr, "\n");
  JSLOG("scan stats:\n\n");
  CLOG(stderr, "    > duration:    %.2fs\n", dur);
  CLOG(stderr, "    > requests:    %lu (%.1f req/s)\n", num_requests, rps);
  humanize_bytes(__atomic_load_n(&g_total_bytes, __ATOMIC_RELAXED),
                 hbuf, sizeof(hbuf));
  CLOG(stderr, "    > downloaded:  %s / %lu lines / %lu words\n", hbuf,
       __atomic_load_n(&g_total_lines, __ATOMIC_RELAXED),
       __atomic_load_n(&g_total_words, __ATOMIC_RELAXED));
  CLOG(stderr,
       "    > codes:       1xx=%lu 2xx=%lu 3xx=%lu 4xx=%lu 5xx=%lu other=%lu\n",
       __atomic_load_n(&g_codes[1], __ATOMIC_RELAXED),
       __atomic_load_n(&g_codes[2], __ATOMIC_RELAXED),
       __atomic_load_n(&g_codes[3], __ATOMIC_RELAXED),
       __atomic_load_n(&g_codes[4], __ATOMIC_RELAXED),
       __atomic_load_n(&g_codes[5], __ATOMIC_RELAXED),
       __atomic_load_n(&g_codes[0], __ATOMIC_RELAXED));
  CLOG(stderr, "    > hits:        %lu\n",
       __atomic_load_n(&g_total_hits, __ATOMIC_RELAXED));
  CLOG(stderr, "\n");
}


/* curl progress callback for fast bail on ctrl+c. returning non-zero
 * makes curl abort the in-flight transfer with CURLE_ABORTED_BY_CALLBACK,
 * so we don't have to wait for req_timeout to release the worker */
static int xferinfo_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                       curl_off_t ultotal, curl_off_t ulnow)
{
  (void) clientp; (void) dltotal; (void) dlnow;
  (void) ultotal; (void) ulnow;
  return g_interrupted ? 1 : 0;
}


/* attack worker thread */
static void *attack(job_T *job)
{
  curl_off_t real_size = 0, size = 0, crtime = 0;
  register double bytes = 0, rtime = 0;
  register size_t i = 0;
  size_t my_jobno = 0;
  long code = 0;
  char suf = 'B';
  CURL *eh = NULL;
  body_stats_T stats = {0};
  char *ctype = NULL;       /* libcurl-owned, valid until cleanup */

  /* bail before claiming a job slot - that way g_curjob stays at the
   * highest "really started" index for accurate session save */
  if (g_interrupted) {
    return NULL;
  }

  /* atomic fetch-and-add so concurrent workers don't lose increments
   * or race on the modulo-print check. counter is file-scope so we can
   * reset it between recursion levels */
  my_jobno = __atomic_fetch_add(&g_curjob, 1, __ATOMIC_RELAXED);
  if (my_jobno % 337 == 0) {
    __STATUS;
  }

  /* duplicate easy handle here (in worker) so we don't pre-allocate
   * num_attack_urls easy handles upfront (huge memory saver) */
  eh = curl_easy_duphandle(job->opts->curl->eh);
  if (eh == NULL) {
    return NULL;
  }

  /* opt-in body capture for -b/-B regex matching. only allocate when
   * the user asked for it - otherwise write_cb's buf branch is a noop
   * and we save 1MB per concurrent request. +1 byte for the NUL we
   * write before regexec since POSIX regexec needs a C-string */
  if (job->opts->body_match_set || job->opts->body_exclude_set) {
    stats.buf = xcalloc(1, BODY_CAPTURE_MAX + 1);
    stats.buf_cap = BODY_CAPTURE_MAX;
  }
  /* per-request stats: write_cb fills these while curl streams the body */
  curl_easy_setopt(eh, CURLOPT_WRITEDATA, &stats);

  /* progress cb so ctrl+c aborts in-flight requests fast */
  curl_easy_setopt(eh, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(eh, CURLOPT_XFERINFOFUNCTION, xferinfo_cb);

  /* overwrite default UA with random ones if requested */
  if (job->opts->rand_ua == ON) {
    curl_easy_setopt(eh, CURLOPT_USERAGENT, get_rand_useragent());
  }

  /* make http request */
  if (job->opts->delay != 0) {
    sleep(job->opts->delay);
  }
  do_req(job->url, eh, job->opts->curl->sh);

  /* get needed infos from http response. ctype points to libcurl-owned
   * memory that's valid until curl_easy_cleanup() - we hand it to
   * emit_hit() before the cleanup, so no need to copy. NULL when the
   * server didn't send a Content-Type header (emit_hit normalizes) */
  curl_easy_getinfo(eh, CURLINFO_RESPONSE_CODE, &code);
  curl_easy_getinfo(eh, CURLINFO_SIZE_DOWNLOAD_T, &size);
  curl_easy_getinfo(eh, CURLINFO_TOTAL_TIME_T, &crtime);
  curl_easy_getinfo(eh, CURLINFO_CONTENT_TYPE, &ctype);

  /* fold per-request data into the global scan stats */
  __atomic_fetch_add(&g_total_bytes, stats.bytes, __ATOMIC_RELAXED);
  __atomic_fetch_add(&g_total_lines, stats.lines, __ATOMIC_RELAXED);
  __atomic_fetch_add(&g_total_words, stats.words, __ATOMIC_RELAXED);
  {
    size_t bucket = 0;
    if (code >= 100 && code < 200) bucket = 1;
    else if (code >= 200 && code < 300) bucket = 2;
    else if (code >= 300 && code < 400) bucket = 3;
    else if (code >= 400 && code < 500) bucket = 4;
    else if (code >= 500 && code < 600) bucket = 5;
    __atomic_fetch_add(&g_codes[bucket], 1UL, __ATOMIC_RELAXED);
  }

  /* convert response sizes - check largest unit first, otherwise the
   * KBYTE branch swallows everything bigger than 1KB */
  bytes = real_size = size;
  if (size >= GBYTE) {
    bytes = (double) size / GBYTE;
    suf = 'G';
  } else if (size >= MBYTE) {
    bytes = (double) size / MBYTE;
    suf = 'M';
  } else if (size >= KBYTE) {
    bytes = (double) size / KBYTE;
    suf = 'K';
  }

  /* convert time sizes */
  rtime = crtime / 1000000.00;

  /* print shit we are interested in. exclude given status codes. */
  for (i = 0; i < job->opts->num_http_ex_codes; ++i) {
    if (code == job->opts->http_ex_codes[i]) {
      goto out;
    }
  }

  /* response size filter (-m/-M). 0 = off. compared against real_size
   * (curl_off_t) which is the actual downloaded body length. cuts out
   * jumbo random crap and tiny noise without touching the wildcard
   * fingerprint table */
  if (job->opts->min_resp_size > 0 &&
      (long long) real_size < job->opts->min_resp_size) {
    goto out;
  }
  if (job->opts->max_resp_size > 0 &&
      (long long) real_size > job->opts->max_resp_size) {
    goto out;
  }

  /* body content regex filters (-b match-only / -B exclude). NUL-term
   * the captured prefix so POSIX regexec sees a C-string. evaluated
   * BEFORE smart-mode wildcard/cluster checks so filtered hits don't
   * count toward suppression thresholds. note: regexec stops at the
   * first NUL in the body, so binary content with embedded NULs only
   * matches against the prefix - rare in practice for HTTP bodies */
  if (stats.buf != NULL) {
    stats.buf[stats.buf_len] = '\0';
    if (job->opts->body_match_set &&
        regexec(&job->opts->body_match_re, stats.buf, 0, NULL, 0) != 0) {
      goto out;
    }
    if (job->opts->body_exclude_set &&
        regexec(&job->opts->body_exclude_re, stats.buf, 0, NULL, 0) == 0) {
      goto out;
    }
  }

  /* code 0 = curl failure (no http response at all). everything else
   * is a real response - the user's -x list above is the only filter
   * for status codes, and an empty body is still a hit (302/401/204
   * commonly carry no body) */
  if (code != HTTP_ZERO) {
    if (job->opts->smart == true) {
      /* phase 1: skip hit if (code, size) matches any of the wildcard
       * fingerprints captured during startup probes */
      for (i = 0; i < job->opts->wcard.num_fps; ++i) {
        if (code == job->opts->wcard.fps[i].resp_code &&
            real_size == job->opts->wcard.fps[i].resp_size) {
          goto out;
        }
      }
      /* phase 2: runtime cluster detection. once we see >=N hits with
       * the same (code, size_bucket), suppress further matches */
      if (job->opts->hits) {
        size_t bucket = 0;
        int dec = hit_table_check(job->opts->hits, code, real_size, &bucket);
        if (dec == HC_SUPPRESSED) {
          goto out;
        }
        if (dec == HC_TRIGGER) {
          /* bare \n FIRST so we land on a fresh line (the \r-overwritten
           * "scanning X / Y" status line stays intact above). emitting
           * the \n inside WSLOG's fmt would split "[!] " from the text.
           * trailing \n AFTER for visual symmetry: the cluster notice
           * gets blank lines on both sides so it stands out from the
           * surrounding hit rows */
          SLOG("\n");
          WSLOG("cluster detected: code=%ld size~%luB (>=%u hits), "
                "suppressing further matches\n\n",
                code, (unsigned long)(bucket * HIT_BUCKET_SIZE),
                job->opts->cluster_threshold);
          goto out;
        }
      }
    }
    /* found hit! */
    __atomic_fetch_add(&g_total_hits, 1UL, __ATOMIC_RELAXED);
    emit_hit(job->logs, job->url, code, bytes, suf,
             (unsigned long long) real_size,
             (unsigned long) stats.lines, (unsigned long) stats.words, rtime,
             ctype);

    /* recursion candidate: url ends with '/', code looks 'real', we
     * still have depth budget left, and it's not on the exclude list */
    if (job->opts->recurse_depth > 0 &&
        g_cur_level < job->opts->recurse_depth &&
        is_recursable(code)) {
      size_t ulen = strlen(job->url);
      if (ulen > 0 && job->url[ulen - 1] == '/' &&
          !path_excluded(job->url, job->opts)) {
        dir_queue_add(&g_dirs, job->url);
      }
    }
  }

out:
  /* unified cleanup so every early-return path frees the body buffer
   * (when allocated) and the duplicated easy handle */
  free(stats.buf);
  curl_easy_cleanup(eh);

  return NULL;
}


/* free + rebuild opts->attack_urls for a new base url. used between
 * recursion levels - we re-read the wordlist (cheap vs. caching) and
 * re-run build_urls for the new target */
static void rebuild_attack_urls(opts_T *opts, const char *base_url)
{
  char **tmpwords = NULL, **tptr = NULL;
  size_t i = 0, num_words = 0;

  /* nuke previous attack_urls */
  if (opts->attack_urls != NULL) {
    for (tptr = opts->attack_urls; *tptr != NULL; ++tptr) {
      free(*tptr);
    }
    free(opts->attack_urls);
    opts->attack_urls = NULL;
  }
  opts->num_attack_urls = 0;

  tmpwords = read_lines(opts->wordlist, 0, &num_words, '\n');
  if (tmpwords == NULL) {
    return;
  }

  opts->attack_urls = build_urls(base_url, tmpwords, num_words,
                                 opts->extens, opts->num_extens);

  for (tptr = opts->attack_urls; *tptr != NULL; ++tptr,
       ++opts->num_attack_urls);

  for (i = 0; i < num_words + 1; ++i) {
    free(tmpwords[i]);
  }
  free(tmpwords);
}


/* run one scan pass: dispatch all attack_urls through the threadpool.
 * single iteration in non-recursive mode, called once per target in
 * recursive mode. start_offset > 0 = resume mode, skip first N urls */
static void scan_one(opts_T *opts, FILE *const logs[LOG_FMT_COUNT],
                     size_t start_offset)
{
  register size_t i = 0;
  job_T **job = NULL;
  threadpool thpool = NULL;

  /* init progress counter to start_offset BEFORE the early-return so
   * the caller's `total_reqs += g_curjob - start_offset` math always
   * yields 0 for a no-op call. otherwise g_curjob would still hold the
   * stale value from the previous scan_one() and get double-counted */
  __atomic_store_n(&g_curjob, start_offset, __ATOMIC_RELAXED);

  if (opts->num_attack_urls == 0 || start_offset >= opts->num_attack_urls) {
    return;
  }

  job = xcalloc(opts->num_attack_urls, sizeof(*job));
  thpool = thpool_init(opts->threads);

  for (i = start_offset; i < opts->num_attack_urls; ++i) {
    int f;
    job[i] = xcalloc(1, sizeof(job_T));
    job[i]->opts = opts;
    for (f = 0; f < LOG_FMT_COUNT; ++f) {
      job[i]->logs[f] = logs[f];
    }
    job[i]->url = opts->attack_urls[i];
    thpool_add_work(thpool, (void *) attack, (void *) job[i]);
  }

  thpool_wait(thpool);
  thpool_destroy(thpool);

  for (i = start_offset; i < opts->num_attack_urls; ++i) {
    free(job[i]);
  }
  free(job);
  SLOG("\n");
}


/* start scanning. when -d > 0 we keep diving into found dirs up to
 * recurse_depth additional levels. dir queue is filled by workers,
 * drained by us between levels. cumulative stats across all levels */
void launch_attack(opts_T *opts)
{
  threadpool dummy = NULL;  /* only needed for early-exit cleanup */
  FILE *logs[LOG_FMT_COUNT] = { NULL };
  unsigned long total_reqs = 0;

  (void) dummy;

  /* init pthread locks */
  if (init_locks() == false) {
    free_lulzbuster(opts);
    __EXIT_FAILURE;
  }

  /* alloc + init the runtime cluster table only when smart mode is on */
  if (opts->smart == true) {
    opts->hits = xcalloc(1, sizeof(struct hit_table));
    if (hit_table_init(opts->hits, opts->cluster_threshold) == false) {
      free(opts->hits);
      opts->hits = NULL;
      free_lulzbuster(opts);
      __EXIT_FAILURE;
    }
  }

  /* init dir queue when recursion is on */
  if (opts->recurse_depth > 0) {
    if (dir_queue_init(&g_dirs) == false) {
      free_lulzbuster(opts);
      __EXIT_FAILURE;
    }
    /* on resume, seed the queue with the dirs we found in the prev
     * session so they get picked up by the recursion loop later */
    if (opts->resume_dirs != NULL) {
      size_t r;
      for (r = 0; r < opts->num_resume_dirs; ++r) {
        if (opts->resume_dirs[r]) {
          dir_queue_add(&g_dirs, opts->resume_dirs[r]);
        }
      }
    }
  }

  /* open one file per selected format. CSV gets a header only when
   * the file is brand-new/empty so re-running just appends rows
   * cleanly. ftell() after fopen("a+") is unreliable across libc
   * impls, hence the stat() upfront */
  {
    int f;
    for (f = 0; f < LOG_FMT_COUNT; ++f) {
      struct stat st;
      int needs_header;
      if (!(opts->log_formats & (1u << f)) || opts->log_paths[f] == NULL) {
        continue;
      }
      needs_header = (f == LOG_FMT_CSV) &&
                     (stat(opts->log_paths[f], &st) != 0 || st.st_size == 0);
      logs[f] = fopen(opts->log_paths[f], "a+");
      if (logs[f] == NULL) {
        int g;
        for (g = 0; g < f; ++g) if (logs[g]) fclose(logs[g]);
        free_lulzbuster(opts);
        err(E_OLOG);
      }
      if (needs_header) log_csv_header(logs[f]);
    }
  }

  /* mark scan start - end stamp taken after the level loop */
  clock_gettime(CLOCK_MONOTONIC, &g_t_start);

  /* level 0: scan opts->start_url with already-built attack_urls.
   * resume_word_offset is 0 unless we loaded a session file */
  g_cur_level = 0;
  JSLOG(HEADLINE);
  scan_one(opts, logs, opts->resume_word_offset);
  total_reqs += __atomic_load_n(&g_curjob, __ATOMIC_RELAXED) -
                opts->resume_word_offset;

  /* ctrl+c during level 0: snapshot the dir queue, print partial stats
   * (so the user sees what was covered before the interrupt) and write
   * the session. session save is best-effort - on failure we just exit,
   * the user still got the interrupt msg */
  if (g_interrupted) {
    char **qd = NULL;
    size_t qd_n = 0;
    unsigned long woff = __atomic_load_n(&g_curjob, __ATOMIC_RELAXED);

    if (opts->recurse_depth > 0) {
      dir_queue_drain(&g_dirs, &qd, &qd_n);
    }

    clock_gettime(CLOCK_MONOTONIC, &g_t_end);
    scan_stats_summary(total_reqs);
    if (opts->smart) hit_table_summary(opts->hits);

    if (save_session(opts->session_path, opts, woff, qd, qd_n) == true) {
      JSLOG("session saved to '%s' (word_offset=%lu, %lu queued dirs)\n",
            opts->session_path, woff, (unsigned long) qd_n);
      JSLOG("resume with: lulzbuster -z %s\n", opts->session_path);
    }

    if (qd) {
      size_t i;
      for (i = 0; i < qd_n; ++i) free(qd[i]);
      free(qd);
    }
    kill_locks();
    {
      int f;
      for (f = 0; f < LOG_FMT_COUNT; ++f) {
        if (logs[f]) fclose(logs[f]);
      }
    }
    if (opts->hits) {
      hit_table_destroy(opts->hits);
      free(opts->hits);
      opts->hits = NULL;
    }
    if (opts->recurse_depth > 0) dir_queue_destroy(&g_dirs);
    return;
  }

  /* recursion levels 1..N: drain dir queue, scan each new target */
  while (opts->recurse_depth > 0 && g_cur_level < opts->recurse_depth) {
    char **targets = NULL;
    size_t num_targets = 0, t = 0;

    g_cur_level++;
    dir_queue_drain(&g_dirs, &targets, &num_targets);

    if (num_targets == 0) {
      free(targets);
      break;
    }

    JSLOG("level %u/%u: %lu target(s) to recurse into\n",
          g_cur_level, opts->recurse_depth, (unsigned long) num_targets);

    for (t = 0; t < num_targets; ++t) {
      JSLOG("scanning: %s\n", targets[t]);

      /* re-probe wildcard for this target */
      opts->wcard = check_conn_wildcard(targets[t], opts->proxy,
                                        opts->proxy_creds, opts->in_ssl,
                                        opts->cert_file, opts->key_file,
                                        opts->key_pass, opts->conn_timeout);
      if (!opts->wcard.conn_ok) {
        WSLOG("no connection to %s, skipping\n", targets[t]);
        free(targets[t]);
        continue;
      }

      /* fresh attack urls for this target + reset cluster bookkeeping */
      rebuild_attack_urls(opts, targets[t]);
      if (opts->hits) {
        hit_table_reset(opts->hits);
      }

      scan_one(opts, logs, 0);
      total_reqs += __atomic_load_n(&g_curjob, __ATOMIC_RELAXED);

      free(targets[t]);

      /* interrupt during recursion: free the rest, drop out. session
       * save is level-0 only, so we just print stats and exit */
      if (g_interrupted) {
        size_t r;
        for (r = t + 1; r < num_targets; ++r) free(targets[r]);
        WSLOG("interrupted during recursion - cannot save session "
              "(level >= 1)\n");
        break;
      }
    }
    free(targets);
    if (g_interrupted) break;
  }

  clock_gettime(CLOCK_MONOTONIC, &g_t_end);
  kill_locks();

  {
    int f;
    for (f = 0; f < LOG_FMT_COUNT; ++f) {
      if (logs[f] && fclose(logs[f]) == EOF) {
        err(W_CLOG);
      }
    }
  }

  /* end-of-scan summary: scan stats always, cluster summary if smart on */
  scan_stats_summary(total_reqs);
  if (opts->hits) {
    hit_table_summary(opts->hits);
    hit_table_destroy(opts->hits);
    free(opts->hits);
    opts->hits = NULL;
  }
  if (opts->recurse_depth > 0) {
    dir_queue_destroy(&g_dirs);
  }

  return;
}

