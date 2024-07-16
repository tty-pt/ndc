uname != uname
PREFIX ?= /usr/local
LIBDIR := $(DESTDIR)${PREFIX}/lib
# LIBDIR := ${DESTDIR}/lib/x86_64-linux-gnu


.PHONY:  all install uninstall clean
.SUFFIXES: .so .c .o

node_modules != realpath ..
npm-lib := @tty-pt/qhash
npm-lib := ${npm-lib:%=${node_modules}/%}
RELDIR := .
CFLAGS := -fPIC ${npm-lib:%=-I%/include} -Iinclude -I/usr/include -I/usr/local/include
uname != uname
ldflags-Linux := -lrt
LDFLAGS := -lc -lqhash -lcrypto ${ldflags-${uname}} -lssl ${npm-lib:%=-L%} -L/usr/lib -L/usr/local/lib ${npm-lib:%=-Wl,-rpath,%}
lib-LDFLAGS := ${LDFLAGS} -fPIC -shared
exe-LDFLAGS := -L. -lndc ${LDFLAGS}
LD := ${CC}

all: libndc.so ndc

libndc.so: src/io.o src/ws.o
	${LD} -o $@ src/io.o src/ws.o ${lib-LDFLAGS}

ndc: src/ndc.o
	${LD} -o $@ ${exe-LDFLAGS} src/ndc.o

.c.o:
	${COMPILE.c} -o ${@:%=${RELDIR}/%} ${<:%=${RELDIR}/%}

interface := ndc ws
interface := ${interface:%=include/%.h}

src/io.o: ${interface}
src/ws.o: include/ws.h
libndc.o: ${interface}
ndc.o: ${interface}

install: all
	install -d ${DESTDIR}${PREFIX}/lib/pkgconfig
	install -m 644 libndc.so ${LIBDIR}
	install -m 644 ndc $(DESTDIR)${PREFIX}/bin
	install -m 644 ndc.pc $(DESTDIR)${PREFIX}/lib/pkgconfig
	install -d ${DESTDIR}${PREFIX}/include
	install -m 644 include/ndc.h $(DESTDIR)${PREFIX}/include

uninstall:
	rm -f $(DESTDIR)${PREFIX}/lib/libndc.so \
		$(DESTDIR)${PREFIX}/lib/pkgconfig/ndc.pc \
		$(DESTDIR)${PREFIX}/include/ndc.h

clean:
	rm src/*.o ndc libndc.so
