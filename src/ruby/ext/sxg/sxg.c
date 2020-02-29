#include <ruby.h>
#include <stdio.h>
#include "libsxg.h"
#include "libsxg/internal/sxg_codec.h"

VALUE SxgModule = Qnil;

static VALUE mice_encode(VALUE self, VALUE src) {
  VALUE r = rb_str_buf_new(10);
  if (rb_type(src) == T_STRING) {
    const uint8_t* src_ptr = (uint8_t*)RSTRING_PTR(src);
    size_t src_length = RSTRING_LEN(src);
    size_t expected_size = sxg_mi_sha256_size(src_length, 4096);
    VALUE encoded = rb_str_new("", expected_size);
    VALUE digest = rb_str_new("", 32);
    uint8_t* encoded_ptr = (uint8_t*)RSTRING_PTR(encoded);
    uint8_t* digest_ptr = (uint8_t*)RSTRING_PTR(digest);

    uint8_t digest_stack[32];
    sxg_encode_mi_sha256(src_ptr, src_length, 4096, encoded_ptr, digest_stack);
    // memcpy(digest_ptr, digest_stack, 32);

    // VALUE result_array = rb_ary_new();
    //rb_ary_push(result_array, encoded);
    //rb_ary_push(result_array, digest);
    return rb_str_new2("Hello!");  // result_array;
  }
  return r;
}

void Init_sxg(void) {
  SxgModule = rb_define_module("Sxg");
  rb_define_module_function(SxgModule, "mice_encode", mice_encode, 1);
}
