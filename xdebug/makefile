PATH_PJSIP := $(PWD)/../../build_g/pjsip
CFLAGS := -I$(PATH_PJSIP)/include
CFLAGS += -DPJ_AUTOCONF
CFLAGS += -g
LIBS := $(PATH_PJSIP)/lib/libpj.a -lm -pthread
#LIBS += -framework Cocoa

all: test
clean:
	rm -f test
test: main.c
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
