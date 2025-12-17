#include "db.h"

#include <stddef.h>
#include <stdio.h>

// clang-format off
static const char *s_sql =
  "create table if not exists identities("
    "id integer primary key autoincrement,"
    "handle text not null unique,"
    "ik blob not null," // identity key
    "spk blob not null," // signed prekey
    "spk_sig blob not null,"
    "pqspk blob not null," // last-resort post-quantum signed prekey
    "pqspk_sig blob not null"
  ");"

  "create table if not exists opks(" // one-time prekeys
    "id integer primary key autoincrement,"
    "used integer not null default 0,"
    "for integer not null,"
    "bytes blob not null,"
    "foreign key (for) references identities(id) on delete cascade"
  ");"

  "create table if not exists pqopks(" // signed one-time pqkem prekeys
    "id integer primary key autoincrement,"
    "used integer not null default 0,"
    "for integer not null,"
    "bytes blob not null,"
    "sig blob not null, "
    "foreign key (for) references identities(id) on delete cascade"
  ");";
// clang-format on

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
