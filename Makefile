# itchygen makefile

# files to compile
COMMON_OBJS += itch_common.o rand_util.o pcap.o double_hash.o crc.o ulist.o
ITCHYGEN_OBJS += itchygen.o $(COMMON_OBJS)
ITCHYPARSE_OBJS += itchyparse.o $(COMMON_OBJS)
ITCHYSERV_OBJS += itchyserv.o
ITCHYPING_OBJS += itchyping.o

# libraries to use
ITCHYGEN_LIBS += -lm -lpthread
ITCHYPARSE_LIBS += -lm
ITCHYSERV_LIBS +=
ITCHYPING_LIBS +=

# executables to make
PROGRAMS += itchygen itchyparse itchyserv itchyping

# dependencies
ITCHYGEN_DEP = $(ITCHYGEN_OBJS:.o=.d)
ITCHYPARSE_DEP = $(ITCHYPARSE_OBJS:.o=.d)
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
CFLAGS += -Wall -Wno-write-strings -Wstrict-prototypes -fPIC

# linker flags
LDFLAGS +=

.PHONY:all
all: $(PROGRAMS)

itchygen: $(ITCHYGEN_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(ITCHYGEN_LIBS)

-include $(ITCHYGEN_DEP)

itchyparse: $(ITCHYPARSE_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS) $(ITCHYPARSE_LIBS)

-include $(ITCHYPARSE_DEP)

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
