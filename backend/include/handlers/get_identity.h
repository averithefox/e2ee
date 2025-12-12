#pragma once

#include <mongoose.h>

void handle_get_identity_request(struct mg_connection *c,
                                 struct mg_http_message *hm);
