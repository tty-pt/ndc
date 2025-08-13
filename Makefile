# uname != uname
# ldlibs-Linux := -lrt
LIB-LDLIBS := -lc -lqmap -lcrypto -lssl -lrt
LIB := ndc
INSTALL-BIN := ndc

npm-lib := @tty-pt/qmap @tty-pt/qsys

-include ../mk/include.mk
