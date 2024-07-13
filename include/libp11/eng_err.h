/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_ENG_ERR_H
# define HEADER_ENG_ERR_H

# ifdef  __cplusplus
extern "C" {
# endif

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */

int ERR_load_ENG_strings(void);
void ERR_unload_ENG_strings(void);
void ERR_ENG_error(int function, int reason, char *file, int line);
# define ENGerr(f,r) ERR_ENG_error((f),(r),__FILE__,__LINE__)

/* Error codes for the ENG functions. */

/* Function codes. */
# define ENG_F_CTX_CTRL_LOAD_CERT                         102
# define ENG_F_CTX_CTRL_SET_PIN                           106
# define ENG_F_CTX_ENGINE_CTRL                            105
# define ENG_F_CTX_LOAD_OBJECT                            107
# define ENG_F_CTX_LOAD_CERT                              100
# define ENG_F_CTX_LOAD_KEY                               101
# define ENG_F_CTX_LOAD_PRIVKEY                           103
# define ENG_F_CTX_LOAD_PUBKEY                            104

/* Reason codes. */
# define ENG_R_INVALID_ID                                 100
# define ENG_R_INVALID_PARAMETER                          103
# define ENG_R_OBJECT_NOT_FOUND                           101
# define ENG_R_UNKNOWN_COMMAND                            102

# ifdef  __cplusplus
}
# endif
#endif