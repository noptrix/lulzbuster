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
* session.h                                                                    *
*                                                                              *
* AUTHOR                                                                       *
* noptrix@nullsecurity.net                                                     *
*                                                                              *
*******************************************************************************/


#ifndef SESSION_H
#define SESSION_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <stddef.h>
#include <stdbool.h>


/* own includes */
#include "opts.h"


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* extension used for the per-target session filename. derive_logfile()
 * sees a leading '.' as a non-alnum and would map it to '-', so we pass
 * the bare ext without the dot - the helper appends '.<ext>' itself */
#define SESSION_EXT       "session"

/* current session file format version. bump when keys change */
#define SESSION_VERSION   1


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* serialize opts + word_offset + queued_dirs to <path>. returns true on
 * success. on error prints a warning and returns false - we don't want
 * a save failure to mask the real interrupt */
bool save_session(const char *path, opts_T *opts,
                  unsigned long word_offset,
                  char **queued_dirs, size_t num_queued);

/* parse <path> and populate opts. *word_offset_out and *queued_*_out
 * receive owned heap data the caller must free. mtime/size of opts->
 * wordlist is verified against the saved values; on mismatch we err()
 * out so we don't resume against a different wordlist. returns true on
 * success */
bool load_session(const char *path, opts_T *opts,
                  unsigned long *word_offset_out,
                  char ***queued_dirs_out,
                  size_t *num_queued_out);


#endif
