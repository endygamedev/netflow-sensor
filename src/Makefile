EXPORTER=exporter
COMMON=common
PACKETS=packets

CFLAGS=-std=gnu99 -Wall -Werror -Wpedantic -Wextra
CC=gcc

.PHONY: clean

all: clean exporter

exporter:
	$(CC) $(PACKETS).c $(COMMON).c $(EXPORTER).c -o $(EXPORTER) $(CFLAGS)

clean:
	rm -f $(EXPORTER)
