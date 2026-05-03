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
* lulzbuster.c                                                                 *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <unistd.h>
#include <stdlib.h>


/* own includes */
#include "lulzbuster.h"
#include "checks.h"
#include "help.h"
#include "error.h"
#include "opts.h"
#include "misc.h"
#include "http.h"
#include "attack.h"
#include "signals.h"
#include "session.h"
#include "log.h"


/* main program flow, driver and controller */
int main(int argc, char *argv[])
{
  opts_T *opts;
  int color_on = 0;

  /* color decision happens BEFORE banner so piped/redirected output
   * doesn't get an ansi-puked banner. -N (set later via parse_opts)
   * forces a re-init below */
  color_on = isatty(STDERR_FILENO) && getenv("NO_COLOR") == NULL;
  init_colors(color_on);

  /* prepare env shizzle */
  banner();
  check_argc(argc);
  xsignal(SIGINT,  sig_int); /* ctrl+c */
  xsignal(SIGTERM, sig_int); /* polite kill(1), same graceful save+exit */
  opts = xcalloc(1, sizeof *opts);
  opts->curl = xcalloc(1, sizeof *opts->curl);
  set_default_opts(opts);
  parse_opts(argc, argv, opts);

  /* -N flag forces colors off even on a TTY */
  if (opts->no_color) {
    init_colors(0);
  }

  /* if -z was passed, hydrate opts from session file before further
   * checks. this overrides start_url, wordlist, extens and the smart/
   * recursion/exclude opts saved at interrupt time */
  if (opts->resume_file) {
    JSLOG("resuming from session: %s\n", opts->resume_file);
    if (load_session(opts->resume_file, opts, &opts->resume_word_offset,
                     &opts->resume_dirs, &opts->num_resume_dirs) == false) {
      free_lulzbuster(opts);
      __EXIT_FAILURE;
    }
    JSLOG("session loaded: word_offset=%lu, %lu queued dir(s)\n",
          opts->resume_word_offset, (unsigned long) opts->num_resume_dirs);
    /* re-use the resume path for the next interrupt-save so the user
     * keeps resuming from one canonical file. strdup'd so the same
     * free path covers it as the auto-derived case */
    {
      size_t l = strlen(opts->resume_file);
      opts->session_path = xcalloc(1, l + 1);
      memcpy(opts->session_path, opts->resume_file, l);
    }
  }

  /* logging is opt-in: only set up when user passed -l or -O. -l
   * alone implies the default text format. resolution per format:
   *   - no -l: derive_logfile(start_url, ext)
   *   - -l + single fmt: user-given path used as-is (exact)
   *   - -l + multi fmt: user-given path treated as a stem, with
   *     .<ext> appended per format. a trailing known ext on the
   *     stem is stripped first so '-l foo.log -O all' produces
   *     foo.log/foo.csv/foo.jsonl instead of foo.log.log */
  if (opts->logfile != NULL || opts->log_formats != 0) {
    int popcnt = 0;
    int f = 0;
    if (opts->log_formats == 0) {
      opts->log_formats = LOG_FMT_BIT_TEXT;
    }
    popcnt = __builtin_popcount(opts->log_formats);
    if (opts->start_url != NULL) {
      const char *exts[LOG_FMT_COUNT] = { "log", "csv", "jsonl" };
      size_t stem_len = 0;
      if (opts->logfile != NULL && popcnt > 1) {
        stem_len = strlen(opts->logfile);
        /* trim a trailing .log/.csv/.jsonl so -l foo.log -O all gives
         * foo.{log,csv,jsonl} rather than foo.log.{log,csv,jsonl} */
        for (f = 0; f < LOG_FMT_COUNT; ++f) {
          size_t el = strlen(exts[f]);
          if (stem_len > el + 1 &&
              opts->logfile[stem_len - el - 1] == '.' &&
              strcmp(opts->logfile + stem_len - el, exts[f]) == 0) {
            stem_len -= el + 1;
            break;
          }
        }
      }
      for (f = 0; f < LOG_FMT_COUNT; ++f) {
        if (!(opts->log_formats & (1u << f))) continue;
        if (opts->logfile == NULL) {
          opts->log_paths[f] = derive_logfile(opts->start_url, exts[f]);
          opts->own_log_paths[f] = true;
        } else if (popcnt == 1) {
          opts->log_paths[f] = (char *) opts->logfile;
          opts->own_log_paths[f] = false;
        } else {
          size_t el = strlen(exts[f]);
          char *p = xcalloc(1, stem_len + 1 + el + 1);
          memcpy(p, opts->logfile, stem_len);
          p[stem_len] = '.';
          memcpy(p + stem_len + 1, exts[f], el);
          opts->log_paths[f] = p;
          opts->own_log_paths[f] = true;
        }
      }
    }
  }

  /* derive a per-target session filename from start_url (same scheme as
   * -O auto-derived logs). lets multiple scans run in the same cwd
   * without clobbering each other's resume state. only set when not
   * resuming - on -z we already have the path the user pointed at and
   * we want to reuse it on the next interrupt */
  if (opts->start_url != NULL && opts->session_path == NULL) {
    opts->session_path = derive_logfile(opts->start_url, SESSION_EXT);
  }

  JSLOG("preparing env\n");
  check_opts(opts);
  check_args(opts);

  /* arm global timeout if user asked for one. SIGALRM handler sets
   * g_interrupted which workers + main poll, so -T behaves like a
   * self-fired ctrl+c and a session file gets written for resume.
   * note: in-flight requests still finish (bounded by -R/-C) so the
   * actual exit can lag a bit past glob_timeout */
  if (opts->glob_timeout != OFF) {
    xsignal(SIGALRM, sig_alrm);
    alarm(opts->glob_timeout);
  }

  /* set extensions and attack urls */
  JSLOG("building attack urls\n");
  set_extensions(opts);
  set_attack_urls(opts);

  /* init curl stuff */
  if (init_http(opts->curl) == false) {
    free_lulzbuster(opts);
    __EXIT_FAILURE;
  }

  /* tcp connection check before we continue */
  JSLOG("connection check\n");
  opts->wcard = check_conn_wildcard(opts->start_url, opts->proxy,
                                    opts->proxy_creds, opts->in_ssl,
                                    opts->cert_file, opts->key_file,
                                    opts->key_pass, opts->conn_timeout);
  if (!opts->wcard.conn_ok) {
    ESLOG("could not connect to: %s\n", opts->start_url);
    free_lulzbuster(opts);
    __GAME_OVER;
    __EXIT_FAILURE;
  }
  JSLOG("connection ok\n");

  /* check for wildcard !HTTP-404 response. we fired several probes with
   * different URL shapes - any of them returning 200 means the site
   * answers ok to bullshit URLs, expect false-positives */
  JSLOG("wildcard check\n");
  if (opts->wcard.any_http_ok) {
    WSLOG("wildcard 200 response detected on probe(s)\n");
  } else {
    GSLOG("lulz! no wildcard 200 detected\n");
  }
  JSLOG("captured %zu unique wildcard fingerprint(s) from %d probes\n",
        opts->wcard.num_fps, MAX_WCARD_PROBES);

  /* set desired http options and show final options */
  if (set_http_options(opts) == false) {
    free_lulzbuster(opts);
    __EXIT_FAILURE;
  }
  print_opts(opts);

  /* real game */
  __GAME_START;
  launch_attack(opts);

  /* end game */
  free_lulzbuster(opts);
  __GAME_OVER;

  return 0;
}


/* default free() right before we exit. note: previous free()s in conjuction
 * with fatal errors (exit()s) otherwise double/multi frees would occur.
 * own_* flags decide whether a field's entries are heap-owned by us
 * (strdup'd from session) or just pointers into argv */
void free_lulzbuster(opts_T *opts)
{
  char **tptr = NULL;

  /* curl stuff here */
  cleanup_http(opts->curl);

  /* free attack_urls (always heap-built by build_urls) */
  if (opts->attack_urls != NULL) {
    for (tptr = opts->attack_urls; *tptr != NULL; ++tptr) {
      free(*tptr);
    }
  }
  free(opts->attack_urls);

  /* extens / exclude_paths: deep-free entries only if session-loaded */
  if (opts->extens != NULL) {
    if (opts->own_extens) {
      for (tptr = opts->extens; *tptr != NULL; ++tptr) free(*tptr);
    }
    free(opts->extens);
  }
  if (opts->exclude_paths != NULL) {
    if (opts->own_exclude_paths) {
      for (tptr = opts->exclude_paths; *tptr != NULL; ++tptr) free(*tptr);
    }
    free(opts->exclude_paths);
  }

  /* start_url / wordlist: heap only if hydrated by load_session */
  if (opts->own_start_url) free((char *) opts->start_url);
  if (opts->own_wordlist)  free((char *) opts->wordlist);
  /* per-format logfile paths heap-owned only when derive_logfile()
   * built them. argv-owned slots (single-format -l) skipped */
  {
    int f;
    for (f = 0; f < LOG_FMT_COUNT; ++f) {
      if (opts->own_log_paths[f]) free(opts->log_paths[f]);
    }
  }
  /* session_path is always heap-owned (derive_logfile or strdup'd from
   * resume_file). NULL-safe free */
  free(opts->session_path);

  /* body regex filters: regfree() releases compiled state owned by
   * regcomp(). guarded by the *_set flags because regex_t has no
   * "compiled?" sentinel and regfree on uninitialized state is UB */
  if (opts->body_match_set)   regfree(&opts->body_match_re);
  if (opts->body_exclude_set) regfree(&opts->body_exclude_re);

  if (opts->resume_dirs != NULL) {
    size_t i;
    for (i = 0; i < opts->num_resume_dirs; ++i) free(opts->resume_dirs[i]);
    free(opts->resume_dirs);
  }
  free(opts->http_ex_codes);
  free(opts->http_method);
  free(opts->curl);
  free(opts);

  return;
}


/* free() parsed_url members */
void free_parsed_url(url_T url)
{
  free(url.scheme);
  free(url.host);
  free(url.port);
  free(url.path);

  return;
}

