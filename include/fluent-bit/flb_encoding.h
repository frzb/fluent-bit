/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>

#if !defined(FLB_ENCODING_H) && defined(FLB_HAVE_REGEX)
#define FLB_ENCODING_H


#include <fluent-bit/flb_config.h>

#define FLB_ENCODING_UTF8     "utf8"
#define FLB_ENCODING_LATIN1   "latin1"
#define FLB_ENCODING_CP1252   "cp1252"

#define FLB_ENCODING_F_ALWAYS_ALLOC   0x0001
#define FLB_ENCODING_F_IGNORE_ERRORS  0x0002

#define FLB_ENCODING_UNKNOWN_ENCODING -3
#define FLB_ENCODING_NOT_SUPPORTED    -2
#define FLB_ENCODING_ERROR            -1
#define FLB_ENCODING_SUCCESS           0
#define FLB_ENCODING_SAME              1


struct flb_encoding {
    char *name;
    char  max_bytes;
    char  is_utf8;

    int   state;
    void *opt;
    int (*to_utf8)(struct flb_encoding *encoding,
                   char *buf, size_t buf_len,
                   char **out_buf, size_t *out_len,
                   int flags);
    int (*from_utf8)(struct flb_encoding *encoding,
                     char *buf, size_t buf_len,
                     char **out_buf, size_t *out_len,
                     int flags);
    int (*to_codepoint)(struct flb_encoding *encoding, int *codeop, char *s, int len);
    int (*from_codepoint)(struct flb_encoding *encoding, int *codeop, char *s, int len);    
};


struct flb_encoding *flb_get_encoding(char *encoding_name);

int flb_decode_to_utf8(struct flb_encoding *encoding,
                       char *buf, size_t buf_len,
                       char **out_buf, size_t *out_len,
                       int flags);

int flb_endcode_from_utf8(struct flb_encoding *encoding,
                          char *buf, size_t buf_len,
                          char **out_buf, size_t *out_len,
                          int flags);

#endif
