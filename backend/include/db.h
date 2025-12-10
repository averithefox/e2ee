#pragma once

#include <sqlite3.h>

sqlite3 *db;

int db_init(sqlite3 **out, const char *path);

void db_close(sqlite3 *db);
