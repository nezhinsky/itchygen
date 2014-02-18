sbindir ?= $(PREFIX)/sbin

ITCHYGEN_OBJS += itchygen.o rand_util.o pcap.o ulist.o

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

# libraries to use
LIBS += -lm # add libs as needed: -laio -lpthread -lrt

PROGRAMS += itchygen 

ITCHYGEN_DEP = $(ITCHYGEN_OBJS:.o=.d)

#LDFLAGS = -Wl,-E

.PHONY:all
all: $(PROGRAMS)

itchygen: $(ITCHYGEN_OBJS)
#	echo $(CC) $^ -o $@ $(LIBS)
	$(CC) $^ -o $@ $(LDFLAGS) $(LIBS)

-include $(ITCHYGEN_DEP)

%.o: %.c
	$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) -MF $*.d -MT $*.o $*.c

.PHONY: install
install: $(PROGRAMS)
	install -d -m 755 $(DESTDIR)$(sbindir)
	install -m 755 $(PROGRAMS) $(DESTDIR)$(sbindir)

.PHONY: clean
clean:
	rm -f *.[od] *.so $(PROGRAMS) 
