SNIFFER = spoofy
DISSECT = dct

INCLUDES_DIR = includes/
INCLUDES = send.h receive.h arp_cache.h interface.h main.h filter.h format.h strat.h protocols.h types.h

INCLUDES_PRE = $(addprefix $(INCLUDES_DIR),$(INCLUDES))

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
	ARP_CACHE = linux/arp_cache.c
	SEND_RAW = linux/send_raw.c
	RCV_RAW = linux/receive_raw.c
endif

ifeq ($(UNAME_S),Darwin)
	ARP_CACHE = mach/arp_cache.c
	SEND_RAW = mach/send_raw.c
	RCV_RAW = mach/receive_raw.c
endif

SOURCES = main.c send.c receive.c interface.c filter.c strat.c format.c $(ARP_CACHE) $(SEND_RAW) $(RCV_RAW)

$(SNIFFER) : $(SOURCES) $(INCLUDES_PRE)
	gcc -lpthread -I $(INCLUDES_DIR) $(SOURCES) -o $(SNIFFER)

.PHONY: $(DISSECT)
$(DISSECT):
	(cd dissect; make RESULT=$(DISSECT))

.PHONY: all
all : $(SNIFFER) $(DISSECT)

.PHONY: clean
clean :
	(rm $(SNIFFER); cd dissect; make clean)
