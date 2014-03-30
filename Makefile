# itchygen makefile

# files to compile
ITCHYGEN_OBJS += itchygen.o rand_util.o pcap.o ulist.o crc.o double_hash.o
ITCHYSERV_OBJS += itchyserv.o
ITCHYPING_OBJS += itchyping.o

# libraries to use
ITCHYGEN_LIBS += -lm
ITCHYSERV_LIBS +=
ITCHYPING_LIBS +=

# executables to make
PROGRAMS += itchygen itchyserv itchyping

# dependencies
ITCHYGEN_DEP = $(ITCHYGEN_OBJS:.o=.d)
ITCHYSERV_DEP = $(ITCHYSERV_OBJS:.o=.d)
ITCHYPING_DEP = $(ITCHYPING_OBJS:.o=.d)

# include dirs
INCLUDES += -I.

# compiler flags
CFLAGS += -D_GNU_SOURCE
CFLAGS += $(INCLUDES)
ifneq ($(DEBUG),)
CFLAGS += -g -O0 -ggdb -rdynamic
else
CFLAGS += -g -O2 -fno-strict-aliasing
endif
CFLAGS += -Wall -Wstrict-prototypes -fPIC

# linker flags
LDFLAGS +=

.PHONY:all
all: $(PROGRAMS)

itchygen: $(ITCHYGEN_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(ITCHYGEN_LIBS)

-include $(ITCHYGEN_DEP)

itchyserv: $(ITCHYSERV_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(ITCHYSERV_LIBS)

-include $(ITCHYSERV_DEP)

itchyping: $(ITCHYPING_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(ITCHYPING_LIBS)

-include $(ITCHYPING_DEP)

# compiling and linking
%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

DESTDIR = /usr
sbindir ?= $(PREFIX)/sbin

.PHONY: install
install: $(PROGRAMS)
	install -d -m 755 $(DESTDIR)$(sbindir)
	install -m 755 $(PROGRAMS) $(DESTDIR)$(sbindir)

.PHONY: clean
clean:
	rm -f *.[od] *.so $(PROGRAMS)
