#ifndef WS_H
#define WS_H

#include <unistd.h>
#include <stdarg.h>

int ws_init(int fd, char *buf);
void ws_close(int fd);
int ws_read(int fd, char *data, size_t len);
int ws_write(int fd, const void *data, size_t n, int flags);
int ws_dprintf(int fd, const char *fmt, va_list ap);
int ws_printf(int fd, const char *fmt, ...);

#endif
