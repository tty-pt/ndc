#include "ws.h"
#include "iio.h"
#include "ndc.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#define OPCODE(head) ((unsigned char) (head[0] & 0x0f))
#define PAYLOAD_LEN(head) ((unsigned char) (head[1] & 0x7f))

struct ws_frame {
	char head[2];
	uint64_t pl;
	char mk[4];
	char data[BUFSIZ];
};

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

int
ws_init(int cfd, char *ws_key) {
	fprintf(stderr, "ws_init %d %s\n", cfd, ws_key);
	static char common_resp[]
		= "HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: upgrade\r\n"
		"Sec-Websocket-Protocol: binary\r\n"
		"Sec-Websocket-Accept: 00000000000000000000000000000\r\n\r\n",
		kkey[] = "Sec-WebSocket-Key";
	unsigned char hash[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *mdctx;
	unsigned int hash_len;
	SHA_CTX c;

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(mdctx, ws_key, strlen(ws_key));
	EVP_DigestUpdate(mdctx, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);

	EVP_DigestFinal_ex(mdctx, hash, &hash_len);
	EVP_MD_CTX_free(mdctx);

	b64_ntop(hash, SHA_DIGEST_LENGTH, common_resp + 129, 29);
	memcpy(common_resp + 129 + 28, "\r\n\r\n", 5);
	ndc_low_write(cfd, common_resp, 129 + 28 + 4);
	return 0;
}

int
ws_write(int cfd, const void *data, size_t n, int flags)
{
	unsigned char head[2];
	head[0] = (flags & (DF_BINARY | DF_FIN));
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
	return ndc_low_write(cfd, frame, len + n) < len + n;
}

void
ws_close(int cfd) {
	unsigned char head[2] = { 0x88, 0x02 };
	unsigned code = 1008;

	ndc_low_write(cfd, head, sizeof(head));
	ndc_low_write(cfd, &code, sizeof(code));
}

int
ws_read(int cfd, char *data, size_t len)
{
	struct ws_frame frame;
	uint64_t pl;
	int i, n;

	n = ndc_low_read(cfd, frame.head, sizeof(frame.head));
	if (n != sizeof(frame.head)) {
		fprintf(stderr, "ws_read: bad frame head size\n");
		goto error;
	}

	if (OPCODE(frame.head) == 8)
		return 0;

	pl = PAYLOAD_LEN(frame.head);

	if (pl == 126) {
		uint16_t rpl;
		n = ndc_low_read(cfd, &rpl, sizeof(rpl));
		if (n != sizeof(rpl)) {
			warn("ws_read: bad rpl size\n");
			goto error;
		}
		pl = rpl;
	} else if (pl == 127) {
		uint64_t rpl;
		n = ndc_low_read(cfd, &rpl, sizeof(rpl));
		if (n != sizeof(rpl)) {
			warn("ws_read: bad rpl size 2\n");
			goto error;
		}
		pl = rpl;
	}

	frame.pl = pl;

	n = ndc_low_read(cfd, frame.mk, sizeof(frame.mk) + pl);
	if (n != sizeof(frame.mk) + pl) {
		warn("ws_read: bad frame mk size\n");
		goto error;
	}

	for (i = 0; i < pl; i++)
		frame.data[i] ^= frame.mk[i % 4];

	frame.data[i] = '\0';
        memcpy(data, frame.data, i + 1);
	return pl;

error:
        return -1;
}

int
ws_dprintf(int fd, const char *format, va_list ap)
{
	static char buf[BUFSIZ];
	return ws_write(fd, buf, vsnprintf(buf, sizeof(buf), format, ap), DF_BINARY & DF_FIN);
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
