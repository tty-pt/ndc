PREFIX ?= /usr/local

.PHONY:  all install uninstall clean
.SUFFIXES: .so .c .o

RELDIR := .
CFLAGS := -fPIC -Iinclude -I/usr/include -g
LDFLAGS := -lc -ldb -lcrypto -lrt -lssl -L/usr/lib
lib-LDFLAGS := ${LDFLAGS} -fPIC -shared
exe-LDFLAGS := ${LDFLAGS} -L. -lndc
LD := gcc

all: libndc.so ndc

libndc.so: src/hash.o src/io.o src/ws.o
	${LD} -o $@ $^ ${lib-LDFLAGS}

ndc: src/ndc.o
	${LD} -o $@ $^ ${exe-LDFLAGS}

.c.o:
	${COMPILE.c} -o ${@:%=${RELDIR}/%} ${<:%=${RELDIR}/%}

interface := ndc hash ws
interface := ${interface:%=include/%.h}

src/io.o: ${interface}
src/hash.o: include/hash.h
src/ws.o: include/ws.h
libndc.o: ${interface}
ndc.o: ${interface}

install: all
	install -d ${DESTDIR}${PREFIX}/lib/pkgconfig
	install -m 644 libndc.so $(DESTDIR)${PREFIX}/lib
	install -m 644 ndc $(DESTDIR)${PREFIX}/bin
	install -m 644 ndc.pc $(DESTDIR)${PREFIX}/lib/pkgconfig
	install -d ${DESTDIR}${PREFIX}/include
	install -m 644 include/ndc.h include/hash.h $(DESTDIR)${PREFIX}/include

uninstall:
	rm -f $(DESTDIR)${PREFIX}/lib/libndc.so \
		$(DESTDIR)${PREFIX}/lib/pkgconfig/ndc.pc \
		$(DESTDIR)${PREFIX}/include/ndc.h

clean:
	rm src/*.o ndc libndc.so
