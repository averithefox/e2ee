#pragma once

#include <mongoose.h>
#include <openssl/pem.h>

EVP_PKEY *load_pub_sig_key_from_spki(const uint8_t *buf, size_t len);
EVP_PKEY *load_pub_enc_key_from_spki(const uint8_t *buf, size_t len);
int verify_signature(const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                     size_t sig_len, EVP_PKEY *pkey);
int verify_request(struct mg_http_message *hm);
