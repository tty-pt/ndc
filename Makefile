uname != uname
PREFIX ?= /usr/local
LIBDIR := $(DESTDIR)${PREFIX}/lib
# LIBDIR := ${DESTDIR}/lib/x86_64-linux-gnu


.PHONY:  all install install-bin uninstall clean
.SUFFIXES: .so .c .o

node_modules != realpath ../..
npm-lib := @tty-pt/qhash
npm-lib := ${npm-lib:%=${node_modules}/%}
RELDIR := .
CFLAGS := -g -fPIC -Iinclude -I/usr/local/include ${npm-lib:%=-I%/include}
uname != uname
ldflags-Linux := -lrt
LDFLAGS := -lc -lndc -lqhash -ldb -lcrypto -lssl ${ldflags-${uname}}
LDFLAGS += -L/usr/local/lib -L. ${npm-lib:%=-Wl,-rpath,%}
LD := ${CC}

libndc.so: src/io.o src/ws.o
	${LD} -o $@ src/io.o src/ws.o -fPIC -shared

ndc: src/ndc.o
	${LD} src/ndc.o -o $@ ${LDFLAGS}

.c.o:
	${COMPILE.c} -o ${@:%=${RELDIR}/%} ${<:%=${RELDIR}/%}

interface := ndc ws
interface := ${interface:%=include/%.h}

src/io.o: ${interface}
src/ws.o: include/ws.h
libndc.o: ${interface}
ndc.o: ${interface}

install: libndc.so
	install -d ${DESTDIR}${PREFIX}/lib/pkgconfig
	install -m 644 libndc.so ${LIBDIR}
	install -m 644 ndc.pc $(DESTDIR)${PREFIX}/lib/pkgconfig
	install -d ${DESTDIR}${PREFIX}/include
	install -m 644 include/ndc.h $(DESTDIR)${PREFIX}/include

install-bin: ndc
	install -d ${DESTDIR}${PREFIX}/bin
	install -m 644 ndc $(DESTDIR)${PREFIX}/bin

uninstall:
	rm -f $(DESTDIR)${PREFIX}/lib/libndc.so \
		$(DESTDIR)${PREFIX}/lib/pkgconfig/ndc.pc \
		$(DESTDIR)${PREFIX}/include/ndc.h

clean:
	rm src/*.o ndc libndc.so
