/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_sds.h>

#include "syslog.h"
#include "syslog_conn.h"

static inline void consume_bytes(char *buf, int bytes, int length)
{
    memmove(buf, buf + bytes, length - bytes);
}


static flb_sds_t get_msgpack_map_field(struct msgpack_object obj, char *fieldname) {
    int i;
    int klen;
    int vlen;
    int flen;
    const char *key;
    const char *val;
    ssize_t ret;
    msgpack_object *k;
    msgpack_object *v;

    flen = strlen(fieldname);
    
    for (i = 0; i < obj.via.map.size; i++) {
        k = &obj.via.map.ptr[i].key;
        
        if (k->type != MSGPACK_OBJECT_BIN &&
            k->type != MSGPACK_OBJECT_STR) {
            continue;
        }
        
        if (k->type == MSGPACK_OBJECT_STR) {
            key  = k->via.str.ptr;
            klen = k->via.str.size;
        }
        else {
            key = k->via.bin.ptr;
            klen = k->via.bin.size;
        }

        if(flen == klen && strncmp(key, fieldname, klen) == 0) {

            v = &obj.via.map.ptr[i].val;

            if (v->type == MSGPACK_OBJECT_STR) {
                val  = v->via.str.ptr;
                vlen = v->via.str.size;
            } else if(v->type == MSGPACK_OBJECT_BIN) {
                val  = v->via.bin.ptr;
                vlen = v->via.bin.size;
            } else {
                return NULL;
            }
            return flb_sds_create_len(val, vlen);
        }
    }
    return NULL;
}


static flb_sds_t get_raw_msgpack_map_field(char *data, int bytes, char *fieldname) {
    msgpack_unpacked result;
    msgpack_object root;
    size_t off = 0;
    flb_sds_t value = NULL;
    msgpack_unpacked_init(&result);
    if(msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        root = result.data;
        if (root.type == MSGPACK_OBJECT_MAP) {
            value =  get_msgpack_map_field(root, fieldname);
        }
    }
    msgpack_unpacked_destroy(&result);
    return value;
}


static inline int pack_line(struct flb_syslog *ctx,
                            struct flb_time *time, char *data, size_t data_size)
{
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;
    char *tag = NULL;
    int tag_len = 0;
    flb_sds_t tag_buf = NULL;

    if(ctx->tag_field) {
        tag_buf = get_raw_msgpack_map_field(data, data_size, ctx->tag_field);
        if(tag_buf != NULL) {
            tag = tag_buf;
            tag_len = flb_sds_len(tag_buf);
        }
    }

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_array(&mp_pck, 2);
    flb_time_append_to_msgpack(time, &mp_pck, 0);
    msgpack_sbuffer_write(&mp_sbuf, data, data_size);

    flb_input_chunk_append_raw(ctx->i_ins, tag, tag_len, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if(tag_buf) {
        flb_sds_destroy(tag_buf);
    }

    return 0;
}

int syslog_prot_process(struct syslog_conn *conn)
{
    int len;
    int ret;
    char *p;
    char *eof;
    char *end;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time;
    struct flb_syslog *ctx = conn->ctx;

    eof = p = conn->buf_data;
    end = conn->buf_data + conn->buf_len;

    /* Always parse while some remaining bytes exists */
    while (eof < end) {

        /* Lookup the ending byte */
        eof = conn->buf_data + conn->buf_parsed;
        while (*eof != '\n' && *eof != '\0' && eof < end) {
            eof++;
        }

        /* Incomplete message */
        if (eof == end || (*eof != '\n' && *eof != '\0')) {
            return 0;
        }

        /* No data ? */
        len = (eof - p);
        if (len == 0) {
            consume_bytes(conn->buf_data, 1, conn->buf_len);
            conn->buf_len--;
            conn->buf_parsed = 0;
            conn->buf_data[conn->buf_len] = '\0';
            end = conn->buf_data + conn->buf_len;

            if (conn->buf_len == 0) {
                return 0;
            }

            continue;
        }

        /* Process the string */
        ret = flb_parser_do(ctx->parser, p, len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            pack_line(ctx, &out_time, out_buf, out_size);
            flb_free(out_buf);
        }
        else {
            flb_warn("[in_syslog] error parsing log message");
        }

        conn->buf_parsed += len + 1;
        end = conn->buf_data + conn->buf_len;
        eof = p = conn->buf_data + conn->buf_parsed;
    }

    consume_bytes(conn->buf_data, conn->buf_parsed, conn->buf_len);
    conn->buf_len -= conn->buf_parsed;
    conn->buf_parsed = 0;
    conn->buf_data[conn->buf_len] = '\0';

    return 0;
}

int syslog_prot_process_udp(char *buf, size_t size, struct flb_syslog *ctx)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct flb_time out_time = {0};

    ret = flb_parser_do(ctx->parser, buf, size,
                        &out_buf, &out_size, &out_time);
    if (ret >= 0) {
        if (flb_time_to_double(&out_time) == 0) {
            flb_time_get(&out_time);
        }
        pack_line(ctx, &out_time, out_buf, out_size);
        flb_free(out_buf);
    }
    else {
        flb_warn("[in_syslog] error parsing log message");
        return -1;
    }

    return 0;
}
