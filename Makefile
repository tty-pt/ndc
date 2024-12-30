uname != uname
PREFIX ?= /usr/local
LIBDIR := $(DESTDIR)${PREFIX}/lib
# LIBDIR := ${DESTDIR}/lib/x86_64-linux-gnu


.PHONY:  all install install-bin uninstall clean
.SUFFIXES: .so .c .o

npm-lib := @tty-pt/qhash
npm-root != npm root
npm-root-dir != dirname ${npm-root}
pwd != pwd
libdir := /usr/local/lib ${pwd} ${npm-lib:%=${npm-root}/%} \
	  ${npm-lib:%=${npm-root-dir}/../../%}
RELDIR := .
CFLAGS := -g -fPIC -Iinclude -I/usr/local/include ${npm-lib:%=-I%/include}
uname != uname
ldflags-Linux := -lrt
LDFLAGS := -lc -lqhash -ldb -lcrypto -lssl ${ldflags-${uname}}
LDFLAGS	+= ${libdir:%=-L%} ${libdir:%=-Wl,-rpath,%}
LD := ${CC}

libndc.so: src/io.o src/ws.o
	${LD} -o $@ src/io.o src/ws.o -fPIC -shared ${LDFLAGS}

bin: ndc

ndc: src/ndc.o
	${LD} src/ndc.o -o $@ -lndc ${LDFLAGS}

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
