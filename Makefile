uname != uname
ldlibs-Linux := -lrt
LIB-LDLIBS := -lc -lqmap -lqsys -lcrypto -lssl \
	${ldlibs-${uname}}
LDLIBS := -lndx
LIB := ndc
INSTALL-BIN := ndc
HEADERS := ndc-ndx.h
CFLAGS := -g

npm-lib := @tty-pt/qmap @tty-pt/qsys @tty-pt/ndx

-include ../mk/include.mk
