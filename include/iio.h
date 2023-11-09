#ifndef IIO_H
#define IIO_H

int ndc_low_write(int fd, void *data, size_t len);
int ndc_low_read(int fd, void *to, size_t len);

#endif
