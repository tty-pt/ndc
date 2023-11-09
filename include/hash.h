#ifndef HASH_H
#define HASH_H

#include <stddef.h>

#define SHASH_INIT			hash_init
#define SHASH_PUT(hd, key, data)	hash_put(hd, key, strlen(key), data)
#define SHASH_GET(hd, key)		hash_get(hd, key, strlen(key))
#define SHASH_DEL(hd, key)		hash_del(hd, key, strlen(key))

typedef void (*hash_cb_t)(void *key, size_t key_size, void *data, void *arg);

int hash_init();
void hash_put(int hd, void *key, size_t key_len, void *data);
void *hash_get(int hd, void *key, size_t key_len);
void hash_delete(int hd, void *key, size_t key_len);
void shash_table(int hd, char *table[]);
void hash_iter(int hd, hash_cb_t callback, void *arg);

#endif
