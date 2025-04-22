#include "../include/ws.h"
#include "../include/iio.h"
#include "../include/ndc.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#define OPCODE(head) ((unsigned char) (head[0] & 0x0f))
#define PAYLOAD_LEN(head) ((unsigned char) (head[1] & 0x7f))

enum ws_flags {
	WS_BINARY = 0x2,
	WS_FIN = 0x80,
};

int ws_flags[FD_SETSIZE];

#ifdef __OpenBSD__
int __b64_ntop(unsigned char const *src, size_t srclength,
	       char *target, size_t targsize);
#define b64_ntop(...) __b64_ntop(__VA_ARGS__)
#else

#include <stdint.h>

// https://github.com/yasuoka/base64/blob/master/b64_ntop.c

int
b64_ntop(u_char *src, size_t srclength, char *target, size_t target_size)
{
  int		 i, j, expect_siz;
  uint32_t	 bit24;
  const char	 b64str[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  expect_siz = ((srclength + 2) / 3) * 4 + 1;

  if (target == NULL)
    return (expect_siz);
  if (target_size < expect_siz)
    return (-1);

  for (i = 0, j = 0; i < srclength; i += 3) {
    bit24 = src[i] << 16;
    if (i + 1 < srclength)
      bit24 |= src[i + 1] << 8;
    if (i + 2 < srclength)
      bit24 |= src[i + 2];

    target[j++] = b64str[(bit24 & 0xfc0000) >> 18];
    target[j++] = b64str[(bit24 & 0x03f000) >> 12];
    if (i + 1 < srclength)
      target[j++] = b64str[(bit24 & 0x000fc0) >> 6];
    else
      target[j++] = '=';
    if (i + 2 < srclength)
      target[j++] = b64str[(bit24 & 0x00003f)];
    else
      target[j++] = '=';
  }
  target[j] = '\0';

  return j;
}

#endif

struct ws_frame {
	char head[2];
	uint64_t pl;
	char mk[4];
	char data[BUFSIZ];
} frame_map[FD_SETSIZE];

int
ws_init(int cfd, char *ws_key) {
	fprintf(stderr, "ws_init %d %s\n", cfd, ws_key);
	static char common_resp[]
		= "HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: upgrade\r\n"
		"Sec-Websocket-Protocol: binary\r\n"
		"Sec-Websocket-Accept: 00000000000000000000000000000\r\n\r\n";
	unsigned char hash[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *mdctx;
	unsigned int hash_len;

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(mdctx, ws_key, strlen(ws_key));
	EVP_DigestUpdate(mdctx, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);

	EVP_DigestFinal_ex(mdctx, hash, &hash_len);
	EVP_MD_CTX_free(mdctx);

	b64_ntop(hash, SHA_DIGEST_LENGTH, common_resp + 129, 29);
	memcpy(common_resp + 129 + 28, "\r\n\r\n", 5);
	io[cfd].lower_write(cfd, common_resp, 129 + 28 + 4);
	memset(&frame_map[cfd], 0, sizeof(struct ws_frame));
	ws_flags[cfd] = WS_BINARY | WS_FIN;
	return 0;
}

ssize_t
ws_write(int cfd, void *data, size_t n)
{
	unsigned char head[2];
	head[0] = (ws_flags[cfd] & (WS_BINARY | WS_FIN));
	head[1] = 0;
	size_t len = sizeof(head);
	int smallest = n < 126;
	char frame[2 + (smallest ? 0 : sizeof(uint64_t)) + n];

	if (smallest) {
		head[1] |= n;
		memcpy(frame, head, sizeof(head));
	} else if (n < (1 << 16)) {
		uint16_t nn = htons(n);
		head[1] |= 126;
		memcpy(frame, head, sizeof(head));
		memcpy(frame + sizeof(head), &nn, sizeof(nn));
		len = sizeof(head) + sizeof(nn);
	} else {
		uint64_t nn = htonl(n);
		head[1] |= 127;
		memcpy(frame, head, sizeof(head));
		memcpy(frame + sizeof(head), &nn, sizeof(nn));
		len = sizeof(head) + sizeof(nn);
	}

	memcpy(frame + len, data, n);
	return io[cfd].lower_write(cfd, frame, len + n) < (ssize_t) (len + n);
}

void
ws_close(int cfd) {
	unsigned char head[2] = { 0x88, 0x02 };
	unsigned code = 1008;

	io[cfd].lower_write(cfd, head, sizeof(head));
	io[cfd].lower_write(cfd, (char *) &code, sizeof(code));
}

ssize_t
ws_read(int cfd, void *data, size_t len __attribute__((unused)))
{
	struct ws_frame *frame = &frame_map[cfd];
	uint64_t pl = 0, n, i;

	if (frame->pl)
		goto mk;

	if (frame->head[0] && frame->head[1])
		goto pl;

	errno = 0;
	n = io[cfd].lower_read(cfd, frame->head, sizeof(frame->head));
	if (n == 0)
		return 0;
	if (n != sizeof(frame->head)) {
		if (errno != EAGAIN)
			fprintf(stderr, "ws_read %d: bad frame head size: %llu %d\n", cfd, n, errno);
		goto error;
	}

	if (OPCODE(frame->head) == 8)
		return 0;

pl:	pl = PAYLOAD_LEN(frame->head);

	if (pl == 126) {
		uint16_t rpl;
		n = io[cfd].lower_read(cfd, &rpl, sizeof(rpl));
		if (n != sizeof(rpl)) {
			if (errno != EAGAIN)
				warn("ws_read %d: bad rpl size\n", cfd);
			goto error;
		}
		pl = rpl;
	} else if (pl == 127) {
		uint64_t rpl;
		n = io[cfd].lower_read(cfd, &rpl, sizeof(rpl));
		if (n != sizeof(rpl)) {
			if (errno != EAGAIN)
				warn("ws_read %d: bad rpl size 2\n", cfd);
			goto error;
		}
		pl = rpl;
	}

	frame->pl = pl;

mk:	n = io[cfd].lower_read(cfd, frame->mk, sizeof(frame->mk) + pl);
	if (n != sizeof(frame->mk) + pl) {
		warn("ws_read %d: bad frame mk size\n", cfd);
		goto error;
	}

	for (i = 0; i < pl; i++)
		frame->data[i] ^= frame->mk[i % 4];

	frame->data[i] = '\0';
        memcpy(data, frame->data, i + 1);
	memset(frame, 0, sizeof(struct ws_frame));
	return pl;

error:	return -1;
}

int
ws_dprintf(int fd, const char *format, va_list ap)
{
	static char buf[BUFSIZ];
	ws_flags[fd] = WS_BINARY & WS_FIN;
	return ws_write(fd, buf, vsnprintf(buf, sizeof(buf), format, ap));
}

int
ws_printf(int fd, const char *format, ...)
{
	ssize_t len;
	va_list args;
	va_start(args, format);
	len = ws_dprintf(fd, format, args);
	va_end(args);
	return len;
}
