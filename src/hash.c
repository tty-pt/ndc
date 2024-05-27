#include "hash.h"
#include <err.h>
#include <string.h>

#ifdef __OpenBSD__
#include <db4/db.h>
#else
#include <db.h>
#endif

#define HASH_DBS_MAX 256

DB *hash_dbs[HASH_DBS_MAX];

size_t hash_n = 0;

int
hash_init()
{
	DB **db = &hash_dbs[hash_n];
	if (db_create(db, NULL, 0) || (*db)->open(*db, NULL, NULL, NULL, DB_HASH, DB_CREATE, 0644))
		err(1, "hash_init");
	return hash_n++;
}

void
hash_put(int hd, void *key_r, size_t key_len, void *data_r)
{
	DB *db = hash_dbs[hd];
	DBT key, data;

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	key.data = (void *) key_r;
	key.size = key_len;
	data.data = &data_r;
	data.size = sizeof(void *);

	if (db->put(db, NULL, &key, &data, 0))
		err(1, "hash_put");
}

void *
hash_get(int hd, void *key_r, size_t key_len)
{
	DB *db = hash_dbs[hd];
	DBT key, data;
	int ret;

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = (void *) key_r;
	key.size = key_len;

	ret = db->get(db, NULL, &key, &data, 0);

	if (ret == DB_NOTFOUND)
		return NULL;
	else if (ret)
		err(1, "hash_get");

	return * (void **) data.data;
}

void
hash_del(int hd, void *key_r, size_t len)
{
	DB *db = hash_dbs[hd];
	DBT key;

	memset(&key, 0, sizeof(key));
	key.data = key_r;
	key.size = len;

	if (db->del(db, NULL, &key, 0))
		err(1, "hash_del");
}

void
shash_table(int hd, char *table[]) {
	for (register char **t = table; *t; t++)
		SHASH_PUT(hd, *t, *t + strlen(*t) + 1);
}

void
hash_iter(int hd, hash_cb_t callback, void *arg) {
	DB *db = hash_dbs[hd];
	DBT data, key;
	DBC *cursor;
	int ret;

	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	db->cursor(db, NULL, &cursor, 0);
	while (1)
		if ((ret = cursor->get(cursor, &key, &data, DB_NEXT))) {
			if (ret != DB_NOTFOUND)
				fprintf(stderr, "HASH_ITER: %s\n", db_strerror(ret));
			cursor->close(cursor);
			db->close(db, 0);
			return;
		} else {
			callback(key.data, key.size, * (void **) data.data, arg);
			memset(&data, 0, sizeof(DBT));
		}
}
