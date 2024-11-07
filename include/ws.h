#ifndef WS_H
#define WS_H

#include <unistd.h>
#include <stdarg.h>

int ws_init(int fd, char *buf);
void ws_close(int fd);
ssize_t ws_read(int fd, void *data, size_t len);
ssize_t ws_write(int fd, void *data, size_t n);
int ws_dprintf(int fd, const char *fmt, va_list ap);
int ws_printf(int fd, const char *fmt, ...);

#endif
