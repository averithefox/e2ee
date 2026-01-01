#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#define CURVE25519_PRIVATE_KEY_LENGTH 32
#define CURVE25519_PUBLIC_KEY_LENGTH 32
#define XEDDSA_SIGNATURE_LENGTH 64


uint8_t *xeddsa_sign(const uint8_t *sk_buf, const uint8_t *msg_buf, uintptr_t msg_len);

bool xeddsa_verify(const uint8_t *pk_buf,
                   const uint8_t *msg_buf,
                   uintptr_t msg_len,
                   const uint8_t *sig_buf);
