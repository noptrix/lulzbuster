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
* session.c                                                                    *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


/* sys includes */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>


/* own includes */
#include "session.h"
#include "wrapper.h"
#include "log.h"


/* string-list join with delim. returns NULL on empty input. caller frees */
static char *join_strlist(char **list, size_t n, const char *delim)
{
  size_t i = 0, total = 0, dlen = 0;
  char *out = NULL, *p = NULL;

  if (list == NULL || n == 0) {
    return NULL;
  }
  dlen = strlen(delim);
  for (i = 0; i < n; ++i) {
    if (list[i] == NULL) break;
    total += strlen(list[i]);
    if (i + 1 < n && list[i + 1] != NULL) total += dlen;
  }
  out = xcalloc(1, total + 1);
  p = out;
  for (i = 0; i < n; ++i) {
    if (list[i] == NULL) break;
    size_t l = strlen(list[i]);
    memcpy(p, list[i], l);
    p += l;
    if (i + 1 < n && list[i + 1] != NULL) {
      memcpy(p, delim, dlen);
      p += dlen;
    }
  }
  return out;
}


/* split CSV into a NULL-term char** with each entry strdup'd */
static char **split_csv(const char *src)
{
  size_t cap = 8, n = 0, len = 0;
  const char *p = src, *start = src;
  char **out = NULL;

  if (src == NULL || *src == '\0') {
    return NULL;
  }
  out = xcalloc(cap, sizeof(char *));

  for (;; ++p) {
    if (*p == ',' || *p == '\0') {
      len = (size_t)(p - start);
      if (n + 1 >= cap) {
        cap *= 2;
        out = xrealloc(out, cap * sizeof(char *));
      }
      out[n] = xcalloc(1, len + 1);
      memcpy(out[n], start, len);
      ++n;
      if (*p == '\0') break;
      start = p + 1;
    }
  }
  out[n] = NULL;
  return out;
}


bool save_session(const char *path, opts_T *opts,
                  unsigned long word_offset,
                  char **queued_dirs, size_t num_queued)
{
  FILE *fp = NULL;
  struct stat st;
  size_t i = 0;
  char *extens_csv = NULL;
  char *excl_csv = NULL;

  fp = fopen(path, "w");
  if (fp == NULL) {
    WSLOG("could not open session file '%s' for writing\n", path);
    return false;
  }

  fprintf(fp, "version=%d\n", SESSION_VERSION);
  fprintf(fp, "start_url=%s\n", opts->start_url ? opts->start_url : "");
  fprintf(fp, "wordlist=%s\n", opts->wordlist ? opts->wordlist : "");

  if (opts->wordlist && stat(opts->wordlist, &st) == 0) {
    fprintf(fp, "wordlist_mtime=%lld\n", (long long) st.st_mtime);
    fprintf(fp, "wordlist_size=%lld\n", (long long) st.st_size);
  }

  /* skip synthetic "" entries that set_extensions() prepends/inserts.
   * the bare-word probe is set_extensions()'s job to (re)add at load
   * time, so persisting it here would round-trip a leading comma in
   * the CSV. we filter the "" entries out and only save real user
   * extensions; if nothing's left, skip the key entirely */
  if (opts->extens != NULL && opts->num_extens > 0) {
    char **real = xcalloc(opts->num_extens + 1, sizeof(char *));
    size_t r = 0;
    for (i = 0; i < opts->num_extens; ++i) {
      if (opts->extens[i] && opts->extens[i][0] != '\0') {
        real[r++] = opts->extens[i];
      }
    }
    if (r > 0) {
      extens_csv = join_strlist(real, r, ",");
      if (extens_csv) {
        fprintf(fp, "extens=%s\n", extens_csv);
        free(extens_csv);
      }
    }
    free(real);
  }

  fprintf(fp, "smart=%d\n", (int) opts->smart);
  fprintf(fp, "cluster_threshold=%u\n", opts->cluster_threshold);
  fprintf(fp, "recurse_depth=%u\n", opts->recurse_depth);

  if (opts->exclude_paths != NULL && opts->num_exclude_paths > 0) {
    excl_csv = join_strlist(opts->exclude_paths, opts->num_exclude_paths, ",");
    if (excl_csv) {
      fprintf(fp, "exclude_paths=%s\n", excl_csv);
      free(excl_csv);
    }
  }

  fprintf(fp, "word_offset=%lu\n", word_offset);

  /* queued dirs as one key per line - simpler than escaping */
  if (queued_dirs != NULL) {
    for (i = 0; i < num_queued; ++i) {
      if (queued_dirs[i] != NULL) {
        fprintf(fp, "queued_dir=%s\n", queued_dirs[i]);
      }
    }
  }

  fclose(fp);
  return true;
}


/* trim trailing CR/LF in-place */
static void rstrip(char *s)
{
  size_t l = strlen(s);
  while (l > 0 && (s[l - 1] == '\n' || s[l - 1] == '\r')) {
    s[--l] = '\0';
  }
}


bool load_session(const char *path, opts_T *opts,
                  unsigned long *word_offset_out,
                  char ***queued_dirs_out,
                  size_t *num_queued_out)
{
  FILE *fp = NULL;
  char line[4096];
  char *eq = NULL, *key = NULL, *val = NULL;
  long long saved_mtime = -1, saved_size = -1;
  struct stat st;
  char **qdirs = NULL;
  size_t qdirs_cap = 0, qdirs_n = 0;
  bool saw_version = false;
  bool ok = false;
  /* track which opts fields we hydrated so we can deep-free only those
   * on failure (and not e.g. a string literal from set_default_opts) */
  bool own_start_url = false, own_wordlist = false;
  bool own_extens = false, own_excludes = false;

  *word_offset_out = 0;
  *queued_dirs_out = NULL;
  *num_queued_out = 0;

  fp = fopen(path, "r");
  if (fp == NULL) {
    ESLOG("could not open session file '%s'\n", path);
    return false;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    rstrip(line);
    if (line[0] == '\0' || line[0] == '#') continue;
    eq = strchr(line, '=');
    if (eq == NULL) continue;
    *eq = '\0';
    key = line;
    val = eq + 1;

    if (strcmp(key, "version") == 0) {
      saw_version = true;
      if (atoi(val) != SESSION_VERSION) {
        ESLOG("session file version mismatch (got %s, expected %d)\n",
              val, SESSION_VERSION);
        goto cleanup;
      }
    } else if (strcmp(key, "start_url") == 0) {
      char *dup = xcalloc(1, strlen(val) + 1);
      strcpy(dup, val);
      opts->start_url = dup;
      own_start_url = true;
    } else if (strcmp(key, "wordlist") == 0) {
      char *dup = xcalloc(1, strlen(val) + 1);
      strcpy(dup, val);
      opts->wordlist = dup;
      own_wordlist = true;
    } else if (strcmp(key, "wordlist_mtime") == 0) {
      saved_mtime = atoll(val);
    } else if (strcmp(key, "wordlist_size") == 0) {
      saved_size = atoll(val);
    } else if (strcmp(key, "extens") == 0) {
      /* may override a parse_str_token result from -A. only the outer
       * array is heap-owned in that case, free it before overwriting */
      free(opts->extens);
      opts->extens = split_csv(val);
      own_extens = true;
    } else if (strcmp(key, "smart") == 0) {
      opts->smart = atoi(val) != 0;
    } else if (strcmp(key, "cluster_threshold") == 0) {
      opts->cluster_threshold = (unsigned short int) atoi(val);
    } else if (strcmp(key, "recurse_depth") == 0) {
      opts->recurse_depth = (unsigned short int) atoi(val);
    } else if (strcmp(key, "exclude_paths") == 0) {
      free(opts->exclude_paths);
      opts->exclude_paths = split_csv(val);
      own_excludes = true;
    } else if (strcmp(key, "word_offset") == 0) {
      *word_offset_out = strtoul(val, NULL, 10);
    } else if (strcmp(key, "queued_dir") == 0) {
      if (qdirs_n + 1 >= qdirs_cap) {
        qdirs_cap = qdirs_cap ? qdirs_cap * 2 : 8;
        qdirs = xrealloc(qdirs, qdirs_cap * sizeof(char *));
      }
      qdirs[qdirs_n] = xcalloc(1, strlen(val) + 1);
      strcpy(qdirs[qdirs_n], val);
      ++qdirs_n;
    }
  }

  if (!saw_version) {
    ESLOG("session file missing 'version=' header\n");
    goto cleanup;
  }

  /* sanity: wordlist must still exist with the same mtime + size */
  if (opts->wordlist && saved_mtime >= 0 && saved_size >= 0) {
    if (stat(opts->wordlist, &st) != 0) {
      ESLOG("session: wordlist '%s' is gone\n", opts->wordlist);
      goto cleanup;
    }
    if ((long long) st.st_mtime != saved_mtime ||
        (long long) st.st_size != saved_size) {
      ESLOG("session: wordlist '%s' changed since save - cannot resume\n",
            opts->wordlist);
      goto cleanup;
    }
  }

  *queued_dirs_out = qdirs;
  *num_queued_out = qdirs_n;
  qdirs = NULL;             /* ownership transferred to caller */
  /* publish ownership flags so free_lulzbuster() knows to deep-free
   * the heap-allocated entries (vs. argv pointers from cmdline) */
  opts->own_start_url     = own_start_url;
  opts->own_wordlist      = own_wordlist;
  opts->own_extens        = own_extens;
  opts->own_exclude_paths = own_excludes;
  ok = true;

cleanup:
  if (fp) fclose(fp);
  /* on failure: free qdirs locally + deep-free the opts fields we
   * hydrated. cast away const to free start_url/wordlist (they're
   * declared const but heap-owned by us once we strdup'd into them) */
  if (!ok) {
    if (qdirs) {
      size_t i;
      for (i = 0; i < qdirs_n; ++i) free(qdirs[i]);
      free(qdirs);
    }
    if (own_start_url) {
      free((char *) opts->start_url);
      opts->start_url = NULL;
    }
    if (own_wordlist) {
      free((char *) opts->wordlist);
      opts->wordlist = NULL;
    }
    if (own_extens && opts->extens) {
      char **t;
      for (t = opts->extens; *t != NULL; ++t) free(*t);
      free(opts->extens);
      opts->extens = NULL;
    }
    if (own_excludes && opts->exclude_paths) {
      char **t;
      for (t = opts->exclude_paths; *t != NULL; ++t) free(*t);
      free(opts->exclude_paths);
      opts->exclude_paths = NULL;
    }
  }
  return ok;
}
