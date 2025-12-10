#include "db.h"

#include <stddef.h>
#include <stdio.h>

static const char *s_sql =
    ""
    "create table if not exists identities ("
    "  handle text primary key,"
    "  encryption_key blob not null,"
    "  signing_key blob not null"
    ");"
    ""
    "create table if not exists conversations ("
    "  id integer primary key autoincrement"
    ");"
    ""
    "create table if not exists participants ("
    "  conversation_id integer not null,"
    "  handle text not null,"
    "  primary key (conversation_id, handle),"
    "  foreign key (conversation_id) references "
    "conversations(id) on delete cascade,"
    "  foreign key (handle) references "
    "identities(handle) on delete cascade"
    ");"
    ""
    "create table if not exists messages ("
    "  id integer primary key autoincrement,"
    "  conversation_id integer not null,"
    "  author text not null,"
    "  content text not null,"
    "  signature blob not null,"
    "  foreign key (conversation_id) references "
    "conversations(id) on delete cascade,"
    "  foreign key (author) references "
    "identities(handle) on delete cascade"
    ");";

sqlite3 *db = NULL;

int db_init(sqlite3 **out, const char *path) {
  int err;
  sqlite3 *db;

  if ((err = sqlite3_open_v2(
           path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) < 0) {
    fprintf(stderr, "[%s] %s\n", __func__, sqlite3_errmsg(db));
    return err;
  }

  if ((err = sqlite3_exec(db, s_sql, NULL, NULL, NULL)) < 0) {
    fprintf(stderr, "[%s] %s\n", __func__, sqlite3_errmsg(db));
    return err;
  }

  *out = db;

  return err;
}

void db_close(sqlite3 *db) {
  if (db) sqlite3_close_v2(db);
}
