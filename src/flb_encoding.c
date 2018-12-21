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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>

#include <monkey/mk_core.h>
#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_utf8.h>
#include <fluent-bit/flb_encoding.h>
#include <fluent-bit/flb_mem.h>

extern struct flb_encoding flb_encoding_latin1;

static int buf_copy(char *buf, size_t buf_len,
                    char **out_buf, size_t *out_len) {
    char *out = flb_malloc(buf_len + 1);
    if(out == NULL)
        return -1;
    memcpy(out_buf, buf, buf_len);
    out_buf[buf_len] = 0;
    *out_len = buf_len ;
    *out_buf = out;
    return FLB_ENCODING_SUCCESS;
}


static int decode_same(struct flb_encoding *encoding,
                       char *buf, size_t buf_len,
                       char **out_buf, size_t *out_len,
                       int flags) {
    if(flags & FLB_ENCODING_F_ALWAYS_ALLOC) {
        return buf_copy(buf,buf_len, out_buf, out_len);
    } else {
        *out_buf = NULL;
        *out_len = buf_len;
        return FLB_ENCODING_SAME;
    }
}


// latin1 is straightforward from unicode, because all values are first 256 values of unicode.

static int decode_latin1_to_utf8(struct flb_encoding *encoding,
                                 char *buf, size_t buf_len,
                                 char **out_buf, size_t *out_len,
                                 int flags) {

    int i;
    int off;
    int dlen = 0;
    unsigned char *uptr = (unsigned char*) buf;
    unsigned char *dbuf;

    // latin1 utf8 length is always 1 (< 128) or 2 (128 <= x <= 255)

    for(i=0; i < buf_len; i++) {
        if(uptr[i] >= 128) {
            dlen += 2;
        } else {
            dlen++;
        }
    }
    // no change
    if(dlen == buf_len) {
        if(flags & FLB_ENCODING_F_ALWAYS_ALLOC) {
            return buf_copy(buf,buf_len, out_buf, out_len);
        } else {
            *out_buf = NULL;
            *out_len = buf_len;
            return FLB_ENCODING_SAME;
        }
    }

    dbuf = flb_malloc(dlen+1);
    if(dbuf == NULL) {
        return -1;
    }

    off = 0;
    for(int i=0; i < buf_len; i++) {
        uint32_t ch = uptr[i];
        if(ch < 128) {
            dbuf[off++] = ch;
        } else {
            dbuf[off++] = (ch >> 6) | 0xC0;
            dbuf[off++] = (ch & 0x3F) | 0x80;
        }
    }
    dbuf[off] = 0;
    assert(off == dlen);

    *out_buf = (char*) dbuf;
    *out_len = dlen;

    return FLB_ENCODING_SUCCESS;
}




struct flb_encoding flb_encoding_utf8 = {
    .name      = "utf8",
    .max_bytes = 3,
    .is_utf8   = 1,
    .to_utf8   = decode_same,
    .from_utf8 = decode_same
};

struct flb_encoding flb_encoding_latin1 = {
    .name      = "latin1",
    .max_bytes = 2,
    .is_utf8   = 0,
    .to_utf8   = decode_latin1_to_utf8,
    .from_utf8 = NULL,
};


struct encoding_mapping {
    char *name;
    struct flb_encoding *encoding;
};

struct encoding_mapping flb_encodings[] = {
    { "utf8" ,      &flb_encoding_utf8 },
    { "utf-8" ,     &flb_encoding_utf8 },
    { "latin1",     &flb_encoding_latin1 },
    { "latin-1",    &flb_encoding_latin1 },
    { "iso-8858-1", &flb_encoding_latin1 },
    { "iso8858-1",  &flb_encoding_latin1 },
    { "iso8858-1",  &flb_encoding_latin1 },
    { "iso88581",   &flb_encoding_latin1 },
    { NULL, NULL },
};

struct flb_encoding *flb_get_encoding(char *encoding_name) {
    int len;
    int i;

    // NULL or empty string use default

    if(encoding_name == NULL) {
        return &flb_encoding_utf8;
    }
    len = strlen(encoding_name);
    if(len == 0) {
        return &flb_encoding_utf8;
    }

    for(i=0; flb_encodings[i].name; i++) {
        if(strcasecmp(flb_encodings[i].name, encoding_name) == 0) {
            return flb_encodings[i].encoding;
        }
    }
    flb_error("[flb_encoding] unknown encoding '%s'", encoding_name);
    return NULL;
}


/**
 *  result status:
 *  FLB_ENCODING_SAME    = did not change input use that... (oub_buf == NULL)
 *  FLB_ENCODING_SUCCESS = changed data.  out_buf must be freed after opration (flb_free);
 *  FLB_ENCODING_ERROR   = cound not do encoding/decoding.   (no memory was allocted). (out_buf == NULL)
 */

int flb_decode_to_utf8(struct flb_encoding *encoding,
                       char *buf, size_t buf_len,
                       char **out_buf, size_t *out_len,
                       int flags) {
    if(encoding->to_utf8 != NULL) {
        return (encoding->to_utf8)(encoding, buf, buf_len, out_buf, out_len, flags);
    }
    return FLB_ENCODING_NOT_SUPPORTED;
}

int flb_encode_from_utf8(struct flb_encoding *encoding,
                         char *buf, size_t buf_len,
                         char **out_buf, size_t *out_len,
                         int flags) {
    if(encoding->from_utf8 == NULL) {
        return FLB_ENCODING_NOT_SUPPORTED;
    }
    return (encoding->from_utf8)(encoding, buf, buf_len, out_buf, out_len, flags);
}
