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
* attack.c                                                                     *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <unistd.h>


/* own includes */
#include "attack.h"
#include "log.h"
#include "wrapper.h"
#include "thpool.h"
#include "log.h"
#include "error.h"
#include "lulzbuster.h"
#include "misc.h"


/* static function prototypes */
static void *attack(job_T *);


/* attack worker thread */
static void *attack(job_T *job)
{
  curl_off_t real_size = 0, size = 0, crtime = 0;
  register double bytes = 0, rtime = 0;
  static size_t curjob = 0;
  register size_t i = 0;
  long code = 0;
  char suf = 'B';

  if (curjob % 337 == 0) {
    __STATUS;
  }
  curjob++;

  /* overwrite default UA with random ones if requested */
  if (job->opts->rand_ua == ON) {
    curl_easy_setopt(job->eh, CURLOPT_USERAGENT, get_rand_useragent());
  }

  /* make http request */
  if (job->opts->delay != 0) {
    sleep(job->opts->delay);
  }
  do_req(job->url, job->eh, job->opts->curl->sh);

  /* get needed infos from http response */
  curl_easy_getinfo(job->eh, CURLINFO_RESPONSE_CODE, &code);
  curl_easy_getinfo(job->eh, CURLINFO_SIZE_DOWNLOAD_T, &size);
  curl_easy_getinfo(job->eh, CURLINFO_TOTAL_TIME_T, &crtime);

  /* convert response sizes */
  bytes = real_size = size;
  if (size >= KBYTE) {
    bytes = (double) size / KBYTE;
    suf = 'K';
  } else if (size >= MBYTE) {
    bytes = (double) size / MBYTE;
    suf = 'M';
  } else if (size >= GBYTE) {
    bytes = (double) size / GBYTE;
    suf = 'G';
  }

  /* convert time sizes */
  rtime = crtime / 1000000.00;

  /* print shit we are interested in. exclude given status codes. */
  for (i = 0; i < job->opts->num_http_ex_codes; ++i) {
    if (code == job->opts->http_ex_codes[i]) {
      curl_easy_cleanup(job->eh);
      return NULL;
    }
  }

  if (code != HTTP_ZERO && code != HTTP_NOT_FOUND && real_size != 0) {
    /* do smart checks */
    if (job->opts->smart == TRUE) {
      /* return NULL if equal to our initial wildcard-probe size */
      if (code == job->opts->wcard.resp_code) {
        if (real_size == job->opts->wcard.resp_size) {
          curl_easy_cleanup(job->eh);
          return NULL;
        }
      }
    }
    /* found hit! */
    __HIT(job->logfile);
  }

  /* destroy easy handler */
  curl_easy_cleanup(job->eh);

  return NULL;
}


/* start scanning */
void launch_attack(opts_T *opts)
{
  register size_t i = 0;
  job_T **job = NULL;
  threadpool thpool = NULL;
  FILE *logfile = stderr;

  /* alloc buf for job structs and create/init threadpool */
  job = xcalloc(opts->num_attack_urls, sizeof(*job));
  thpool = thpool_init(opts->threads);

  /* init phtread locks */
  if (init_locks() == FALSE) {
    free(job);
    thpool_destroy(thpool);
    free_lulzbuster(opts);
    __EXIT_FAILURE;
  }

  /* set !stderr logfile */
  if (opts->logfile) {
    logfile = fopen(opts->logfile, "a+");
    if (!logfile) {
      free(job);
      thpool_destroy(thpool);
      free_lulzbuster(opts);
      err(E_OLOG);
    }
  }

  /* initiate needed opts, add attacker threads to pool and fire shit */
  JLOG(HEADLINE);
  for (i = 0; i < opts->num_attack_urls; ++i) {
    job[i] = xcalloc(1, sizeof(job_T));
    job[i]->opts = opts;
    job[i]->logfile = logfile;
    job[i]->url = opts->attack_urls[i];
    job[i]->eh = curl_easy_duphandle(opts->curl->eh);
    thpool_add_work(thpool, (void *) attack, (void *) job[i]);
  }

  /* wait for threads to finish, destroy thpool afterwards and destroy locks */
  thpool_wait(thpool);
  thpool_destroy(thpool);
  kill_locks();

  /* free job */
  for (i = 0; i < opts->num_attack_urls; ++i) {
    free(job[i]);
  }
  free(job);
  if (opts->logfile) {
    if (fclose(logfile) == EOF) {
      err(W_CLOG);
    }
  }
  SLOG("\n");

  return;
}

