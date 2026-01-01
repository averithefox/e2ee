#include "base64.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

char *b64_decode(const char *b64, ssize_t b64_len, size_t *out_len) {
  EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
  if (!ctx) return NULL;

  int len, total_len = 0;
  size_t input_len = b64_len < 0 ? strlen(b64) : b64_len;
  char *output = malloc(input_len);
  if (!output) {
    fprintf(stderr, "[%s:%d] out of memory\n", __func__, __LINE__);
    EVP_ENCODE_CTX_free(ctx);
    return NULL;
  }

  EVP_DecodeInit(ctx);
  EVP_DecodeUpdate(ctx, (unsigned char *)output, &len, (unsigned char *)b64,
                   input_len);
  total_len = len;

  int rc = EVP_DecodeFinal(ctx, (unsigned char *)output + total_len, &len);
  total_len += len;

  EVP_ENCODE_CTX_free(ctx);

  if (rc < 0) {
    free(output);
    return NULL;
  }

  output[total_len] = '\0';
  if (out_len) *out_len = total_len;

  char *shrunk = realloc(output, total_len + 1);
  return shrunk ? shrunk : output;
}
