/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
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

#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>

#include <string.h>
#include <fluent-bit.h>

#include "filter_csv.h"

static int msgpackobj2char(msgpack_object *obj,
                           char **ret_char, int *ret_char_size)
{
    int ret = -1;

    if (obj->type == MSGPACK_OBJECT_STR) {
        *ret_char      = (char*)obj->via.str.ptr;
        *ret_char_size = obj->via.str.size;
        ret = 0;
    }
    else if (obj->type == MSGPACK_OBJECT_BIN) {
        *ret_char      = (char*)obj->via.bin.ptr;
        *ret_char_size = obj->via.bin.size;
        ret = 0;
    }

    return ret;
}

static int parse_char(char *str, int def) {
    if(str == NULL) {
        return 0;
    } else if(*str == 0) {
        return 0;
    } else if(strlen(str) > 1) {
        if(!strcasecmp(str,"none")) {
            return 0;
        } else if(!strcasecmp(str,"default")) {
            return def;            
        } else if(!strcasecmp(str,"amp")) {
            return '&';
        } else if(!strcasecmp(str,"quot")) {
            return '"';
        } else if(!strcasecmp(str,"apos")) {
            return '\'';
        } else if(!strcasecmp(str,"comma")) {
            return ',';
        } else if(!strcasecmp(str,"semicolon")) {
            return ';';
        } else if(!strcasecmp(str,"colon")) {
            return ';';
        } else if(!strcasecmp(str,"hyphen")) {
            return '-';
        } else if(!strcasecmp(str,"period")) {
            return '.';
        } else if(!strcasecmp(str,"pipe")) {
            return '|';
        } else if(!strcasecmp(str,"slash")) {
            return '/';
        } else if(!strcasecmp(str,"equal")) {
            return '=';
        } else if(!strcasecmp(str,"space")) {
            return ' ';
        } else if(!strcasecmp(str,"tab")) {
            return '\t';
        } else if(!strcasecmp(str,"backslash")) {
            return '\\';
        } else {
            flb_error("[filter_csv] bad special char : %s", str);
            return -1;
        }
    } else {
        return *str;
    }
}

static int parse_boolean(char *str, int def) {
    if(!strcmp(str,"1") || !strcasecmp(str,"true") || !strcasecmp(str,"on")) {
        return 1;
    } else if(!strcmp(str,"0") || !strcasecmp(str,"false") || !strcasecmp(str,"off")) {
        return 0;
    } else {
        flb_error("[filter_csv] illegal delete_original");
        return -1;
    }
}


#define ST_START         0
#define ST_NORMAL        1
#define ST_ESCAPE        2
#define ST_QUOTE         3
#define ST_QUOTE_ESCAPE  4
#define ST_QUOTE_END     5
#define ST_ERROR         6

static msgpack_object_str *parse_csv_values(const char *str, char **bufptr, int length, int field_count, int sep, int quote, int escape, int skipSpace) {

    int index;
    int  state;
    int  prev;
    msgpack_object_str *out;
    char *buf;
    char *a;    
    char *b;
    unsigned char *s = (unsigned char*) str;
    unsigned char *ep = s + length;
    
    if((out = flb_calloc(sizeof(msgpack_object_str), field_count + 2)) == NULL) {
        flb_errno();
        return NULL;
    }
    if((buf = flb_calloc(sizeof(char), length + 2)) == NULL) {
        flb_free(out);
        flb_errno();
        return NULL;
    }
    *bufptr = buf;
    b = buf;

    index = 0;
    state = ST_START;
    a = b;
    while(s < ep) {
        int ch = *s++;
        switch(state) {
        case ST_START:
            if(ch == sep && index < field_count) {
                out[index].ptr = a;                
                out[index].size = b - a;
                *b++ = 0;
                a = b;
                index++;
            } else if(quote && ch == quote) {
                state = ST_QUOTE;
                a = b;
            } else if(escape && ch == escape) {
                state = ST_ESCAPE;
                prev  = ST_NORMAL;
            } else if(skipSpace && ch == ' ') {
                state = ST_START;
            } else {
                *b++ = ch;
                state = ST_NORMAL;
            }
            break;
        case ST_NORMAL:
            if(ch == sep && index < field_count) {
                out[index].ptr  = a;
                out[index].size = b - a;                
                *b++ = 0;
                index++;
                a = b;
                state = ST_START;
            } else if(escape && ch == escape) {
                state = ST_ESCAPE;
                prev  = ST_NORMAL;
            } else {
                *b++ = ch;
                state = ST_NORMAL;
            }
            break;
        case ST_QUOTE:
            if(ch == quote) {
                state = ST_QUOTE_END;
            } else if(escape && ch == escape) {
                state = ST_QUOTE_ESCAPE;
                prev = ST_QUOTE;
            } else {
                *b++ = ch;
            }
            break;
            
        case ST_ESCAPE:
        case ST_QUOTE_ESCAPE:            
            switch(ch) {
            case '\'':
                *b++ = '\'';
                break;
            case '\"':
                *b++ = '\"';
                break;
            case '\\':
                *b++ = '\\';
                break;
            case 'n':
                *b++ = '\n';
                break;
            case 'r':
                *b++ = '\r';
                break;
            case 'v':
                *b++ = '\v';
                break;
            case 'f':
                *b++ = '\f';
                break;
            case 't':
                *b++ = '\t';
                break;
            default:
                *b++ = '\\';
                *b++ = ch;
                break;
            }
            state = prev;
            break;
        case ST_QUOTE_END:
            if(ch == sep) {
                out[index].ptr  = a;
                out[index].size = b - a;
                index++;
                *b++ = 0;
                a = b;
                state = ST_START;
            }
            break;
        default:
            abort();
        }
    }
    out[index].ptr  = a;
    out[index].size = b - a;
    index++;
    out[index].ptr  = NULL;
    out[index].size = 0;
    return out;
}


// https://frictionlessdata.io/specs/csv-dialect/

static int csv_configure(struct filter_csv_ctx *ctx,
                         struct flb_filter_instance *f_ins,
                         struct flb_config *config)
{
    char *tmp;
    ctx->message_field = "message";
    ctx->delimiter    = ',';
    ctx->quote        = '\"';
    ctx->escape       = 1;
    ctx->doubleQuote  = 0;
    ctx->skipInitialSpace = 0;
    
    ctx->delete_original = 1;
    ctx->has_empty_values = 0;
    ctx->field_count = 0;

    
    /* message field  (default: "message") */
    tmp = flb_filter_get_property("message_field", f_ins);
    if (tmp) {
        ctx->message_field = flb_strdup(tmp);
    } 

    tmp = flb_filter_get_property("fields", f_ins);
    if (tmp) {
        // lazy way to calculae count of fields
        char *values = flb_strdup(tmp);
        char *s = values;
        char *tok;
        int field_count = 0;
        while((tok = strsep(&s, " \t")) != NULL) {
            field_count++;
            if(field_count >= 100) {
                abort();
            }
        }
        flb_free(values);
        ctx->field_count = field_count;

        ctx->fields = flb_calloc(sizeof(char *), field_count + 1);
        if(ctx->fields == NULL) {
            flb_errno();
            return -1;
        }

        ctx->lengths = flb_calloc(sizeof(int), field_count + 1);
        if(ctx->lengths == NULL) {
            flb_errno();
            flb_free(ctx->fields);
            return -1;
        }

        values = flb_strdup(tmp);
        s = values;
        int index = 0;
        while((tok = strsep(&s, " \t")) != NULL) {
            char *field = flb_strdup(tok);
            if(field == NULL) {
                flb_errno();
                continue;
            }
            ctx->fields[index]  = field;
            ctx->lengths[index] = strlen(field);
            index++;
        }
        flb_free(values);        
    }
    tmp = flb_filter_get_property("delimiter", f_ins);
    if (tmp) {
        ctx->delimiter = parse_char(tmp,',');
    }
    tmp = flb_filter_get_property("escape", f_ins);
    if (tmp) {
        ctx->escape = parse_char(tmp,'\\');
    }
    tmp = flb_filter_get_property("quote", f_ins);
    if (tmp) {
        ctx->quote = parse_char(tmp,'\'');
    }
    
    tmp = flb_filter_get_property("doubleQuote", f_ins);
    if (tmp) {
        ctx->doubleQuote = parse_boolean(tmp, ctx->doubleQuote);
    }

    tmp = flb_filter_get_property("skip_initial_space", f_ins);
    if(tmp) {
        ctx->skipInitialSpace = parse_boolean(tmp, 0);
    }
    
    tmp = flb_filter_get_property("delete_original", f_ins);
    if (tmp) {
        ctx->delete_original = parse_boolean(tmp, 1);
    }

    tmp = flb_filter_get_property("has_empty_values", f_ins);
    if(tmp) {
        ctx->has_empty_values = parse_boolean(tmp, 0);
    }


    if(ctx->field_count <= 0) {
        flb_error("[filter_csv] no fields defined");
        return -1;
    }

    ctx->message_field_length = strlen(ctx->message_field);

    return 0;
}

static int cb_csv_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    (void) f_ins;
    (void) config;
    (void) data;

    struct filter_csv_ctx *ctx = NULL;

    /* Create context */
    ctx = flb_malloc(sizeof(struct filter_csv_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    if ( csv_configure(ctx, f_ins, config) < 0 ){
        flb_free(ctx);
        return -1;
    }

    flb_filter_set_context(f_ins, ctx);

    return 0;
}



static msgpack_object *get_key_value(msgpack_object *map, char *keyValue, int *index)  
{
    msgpack_object_kv *kv;
    int keyLen = strlen(keyValue);
    int mapSize = map->via.map.size;
    char *key_str;
    int   key_len;
    
    kv = map->via.map.ptr;
    for(int i=0; i< mapSize; i++) {
        int ret = msgpackobj2char(&(kv[i].key), &key_str, &key_len);
        if(ret == 0 && key_len == keyLen && !strncasecmp(key_str, keyValue, keyLen)) {
            if(index) {
                *index = i;
            }
            return &kv[i].val;
        }
    }
    return NULL;
}
 
static int cb_csv_filter(void *data, size_t bytes,
                         char *tag, int tag_len,
                         void **ret_buf, size_t *ret_bytes,
                         struct flb_filter_instance *f_ins,
                         void *context,
                         struct flb_config *config)
{
    struct filter_csv_ctx *ctx = context;
    msgpack_unpacked result;
    size_t off = 0;
    (void) f_ins;
    (void) config;
    struct flb_time tm;
    msgpack_object *obj;
    msgpack_object_kv *kv;
    int i;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object *val_object;
    int val_key_index;
    int map_size;
    int new_map_size;
    msgpack_object_str *parsed_values;
    char *buf;
    int cnt = 0;
    int changed = 0;

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);

    
    while (msgpack_unpack_next(&result, data, bytes, &off)) {

        cnt++;

        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }
        
        flb_time_pop_from_msgpack(&tm, &result, &obj);
        
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        map_size = obj->via.map.size;

        msgpack_pack_array(&tmp_pck, 2);
        
        flb_time_append_to_msgpack(&tm, &tmp_pck, 0);

        flb_debug("[filter_csv] here we go (%d)", cnt);
        
        val_key_index = -1;
        val_object = get_key_value(obj, ctx->message_field, &val_key_index);

        if(val_object == NULL || val_object->type != MSGPACK_OBJECT_STR) {
            msgpack_pack_object(&tmp_pck, *obj);
            continue;
        }

        changed++;

        buf = NULL;
        
        parsed_values = parse_csv_values(val_object->via.str.ptr, &buf, val_object->via.str.size, ctx->field_count, ctx->delimiter, ctx->quote, ctx->escape, ctx->skipInitialSpace);

        if(!parsed_values) {
            flb_error("[filter_csv] parsing error");
            flb_free(buf);
            msgpack_unpacked_destroy(&result);
            msgpack_sbuffer_destroy(&tmp_sbuf);
            return FLB_FILTER_NOTOUCH;
        }
        if(buf == NULL) abort();

        new_map_size = map_size;        

        if(ctx->delete_original) {
            new_map_size--;
        } else {
            val_key_index = -1;
        }

        if(ctx->has_empty_values == 0) {
            for(i=0; i < ctx->field_count; i++) {
                if(parsed_values[i].size > 0) {
                    new_map_size++;
                }
            }
        }

        msgpack_pack_map(&tmp_pck, new_map_size);
        
        kv = obj->via.map.ptr;
        for(i=0; i< map_size; i++) {
            if(val_key_index >= 0  && i == val_key_index) {
                continue;
            }
            msgpack_pack_object(&tmp_pck, kv[i].key);
            msgpack_pack_object(&tmp_pck, kv[i].val);
        }
        for(i=0; i < ctx->field_count; i++) {
            if(parsed_values[i].size > 0 || ctx->has_empty_values) {            
                msgpack_pack_str(&tmp_pck, ctx->lengths[i]);
                msgpack_pack_str_body(&tmp_pck,ctx->fields[i], ctx->lengths[i]);
                msgpack_pack_str(&tmp_pck, parsed_values[i].size);
                msgpack_pack_str_body(&tmp_pck,parsed_values[i].ptr ? parsed_values[i].ptr : "", parsed_values[i].size);
            }
        }
        
        flb_free(buf);
        flb_free(parsed_values);
    }

    msgpack_unpacked_destroy(&result);

    if(changed) {
        *ret_buf   = tmp_sbuf.data;
        *ret_bytes = tmp_sbuf.size;
        return FLB_FILTER_MODIFIED;        
    } else {
        msgpack_unpacked_destroy(&result);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        return FLB_FILTER_NOTOUCH;
    }
}
  

static int cb_csv_exit(void *data, struct flb_config *config)
{
    struct filter_csv_ctx *ctx = data;

    if (ctx != NULL) {
        int i;

        for(i=0; i < ctx->field_count; i++) {
            flb_free(ctx->fields[i]);
        }

        flb_free(ctx->message_field);
        flb_free(ctx->fields);
        
        flb_free(ctx);
    }
    return 0;
}

struct flb_filter_plugin filter_csv_plugin = {
    .name         = "csv",
    .description  = "Parse csv fields",
    .cb_init      = cb_csv_init,
    .cb_filter    = cb_csv_filter,
    .cb_exit      = cb_csv_exit,
    .flags        = 0
};
