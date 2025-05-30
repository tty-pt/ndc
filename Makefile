PREFIX ?= /usr/local

.PHONY:  all install install-bin uninstall clean
.SUFFIXES: .so .c .o

npm-lib := @tty-pt/qdb

uname != uname
ldflags-Linux := -lrt
LDFLAGS := -lc -lqdb -ldb -lcrypto -lssl ${ldflags-${uname}}
CFLAGS := -fPIC -Wall -Wextra -Wpedantic
RELDIR := .
LD := ${CC}

-include node_modules/@tty-pt/mk/include.mk
-include ../mk/include.mk

all: lib/libndc.so bin/ndc

lib/libndc.so: src/io.o src/ws.o lib
	${LD} -o $@ src/io.o src/ws.o -fPIC -shared ${LDFLAGS}

bin/ndc: src/ndc.o bin
	${LD} src/ndc.o -o $@ -lndc ${LDFLAGS}

lib bin:
	mkdir $@ 2>/dev/null || true

.c.o:
	${COMPILE.c} -o ${@:%=${RELDIR}/%} ${<:%=${RELDIR}/%}

interface := ndc ws
interface := ${interface:%=include/%.h}

src/io.o: ${interface}
src/ws.o: include/ws.h
libndc.o: ${interface}
ndc.o: ${interface}

install: lib/libndc.so
	install -d ${DESTDIR}${PREFIX}/lib/pkgconfig
	install -m 644 lib/libndc.so ${DESTDIR}${PREFIX}/lib
	install -m 644 ndc.pc $(DESTDIR)${PREFIX}/lib/pkgconfig
	install -d ${DESTDIR}${PREFIX}/include
	install -m 644 include/ndc.h $(DESTDIR)${PREFIX}/include
	install -d ${DESTDIR}${PREFIX}/bin
	install -m 644 bin/ndc $(DESTDIR)${PREFIX}/bin

uninstall:
	rm -f $(DESTDIR)${PREFIX}/lib/libndc.so \
		$(DESTDIR)${PREFIX}/lib/pkgconfig/ndc.pc \
		$(DESTDIR)${PREFIX}/include/ndc.h

clean:
	rm src/*.o bin/ndc lib/libndc.so

.PHONY: all install uninstall
