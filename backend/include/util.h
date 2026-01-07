#pragma once

#include <mongoose.h>
#include <openssl/pem.h>

/**
 * Verifies a signed HTTP request
 * @param hm Pointer to the HTTP message to verify.
 * @param id_key optional pointer to store the ID key on success (must be freed
 * by the caller)
 * @return The identity ID on success (>=0), or a negative HTTP status code on
 * failure.
 */
int64_t verify_request(struct mg_http_message* hm, void** id_key);
