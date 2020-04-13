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


#ifndef MISC_H
#define MISC_H


/*******************************************************************************
 * INCLUDES
 ******************************************************************************/


/* sys includes */
#include <stdio.h>


/* own includes */


/*******************************************************************************
 * MACROS
 ******************************************************************************/


/* data sizes */
#define KBYTE   1024.00
#define MBYTE   1048576.00
#define GBYTE   1073741824.00


/* default line length to read from wordlists via read_lines() */
#define DEF_LINE_LEN  1024


/*******************************************************************************
 * VARS
 ******************************************************************************/


/*******************************************************************************
 * FUNCTION PROTOTYPES
 ******************************************************************************/


/* build urls out of <url> + <line> (read from file) + [extension] */
char **build_urls(const char *, char **, size_t, char **, size_t);

/* read lines from file. kill <lastchar> with 0x00 if given */
char **read_lines(const char *, size_t, size_t *, const int);

/* count lines in a file. wc -l ;) */
size_t count_lines(const char *);

/* convert given string to upper or lower-case */
char *touplow(const char *, const char *);

/* parse string with given delimiter and length */
char **parse_str_token(char *, const char *, const unsigned char);

/* parse string with given delimiter and length to long int values */
long int *parse_str_toint_token(char *, const char *, const unsigned char);


#endif

