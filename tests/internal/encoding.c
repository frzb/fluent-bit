/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_encoding.h>

#include <time.h>
#include "flb_tests_internal.h"

struct encoding_case {
    char *enc;
    char *src;
    char *dst;
};


// a,b,a+",b",c
static char latin1_test1_src[] = { 'a',  'b',  0xe4,          0xf6,           'c',  0 };
static char latin1_test1_dst[] = { 'a',  'b',  0xc3,   0xa4,  0xc3 , 0xb6,    'c',  0 };

static struct encoding_case encoding_tests[] = {
    { .enc = "latin1", .src = (char*) latin1_test1_src,  .dst = (char*) latin1_test1_dst      },
    
    { .enc = "",  .src = "" },
    { .enc = "",  .src = "abc" },

    { .enc ="utf8", .src =  "" },
    { .enc ="utf8", .src = "abcDEF" },
    
    { .enc = "latin1", .src = ""       },
    { .enc = "latin1", .src = "a"      } ,
    { .enc = "latin1", .src = "abcDEF" },
    
    //     { "latin1", { 'a','b' }, { 'a', 'b' } },

    { .enc = NULL, .src = NULL, .dst = NULL },
};


void test_encodings()  
{
    int i;
    int ret;
    char *enc;
    char *src;
    char *dst;    
    int slen;
    int dlen;
    int same;
    char *out_buf;
    size_t out_size;
    struct encoding_case *t;
    struct flb_config *config;
    

    /* Dummy config context */
    config = flb_config_init();

    for(i=0; encoding_tests[i].enc != NULL; i++) {
      t  = &encoding_tests[i];

      TEST_CHECK(t != NULL);
      
      enc = t->enc;
      src = t->src;
      dst = t->dst;

      // printf("(%s)(%s)(%s)\n", enc, src, dst ? dst : "NULL");
      
      slen = strlen(src);

      if(dst == NULL) {
          same = 1;
          dst  = src;
          dlen = slen;
      } else {
          same = 0;
          dlen = strlen(dst);
      }
      
      struct flb_encoding *encoding = flb_get_encoding(enc);
      TEST_CHECK(encoding != NULL && encoding->name != NULL);
      
      out_buf = NULL;
      ret = flb_decode_to_utf8(encoding,
                               src, slen,
                               &out_buf, &out_size,
                               0);
      if(ret == FLB_ENCODING_SUCCESS) {
          TEST_CHECK_(out_size == dlen,"[%d] encoding length mismatch");
          TEST_CHECK_(memcmp(dst,out_buf, out_size) == 0,"[%d] encoding value mismatch (%s)(%s)", i, enc, dst);
      } else if(ret == FLB_ENCODING_SAME) {
          TEST_CHECK_(same,"[%d] should be same (%s)(%s)", i, enc, src);
      } else {
          TEST_CHECK_(0,"[%d] encoding gave error (%d)", i,  ret);
      }
      if(out_buf != NULL) {
          flb_free(out_buf);
      }
    }
    
    flb_config_exit(config);    
}



TEST_LIST = {
    { "test_encodings", test_encodings },
    { 0 }
};

