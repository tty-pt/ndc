#ifndef IIO_H
#define IIO_H

#include <stdio.h>
#include <sys/select.h>

typedef ssize_t (*io_t)(int fd, void *data, size_t len);

struct io {
	io_t read, write, lower_read, lower_write;
};

extern struct io io[FD_SETSIZE];

#endif
