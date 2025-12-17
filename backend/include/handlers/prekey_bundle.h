#pragma once

#include <mongoose.h>

void handle_prekey_bundle_request(struct mg_connection *c,
                                  struct mg_http_message *hm,
                                  struct mg_str *handle);
