CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -Wpedantic -Werror -Wformat-security -fstack-protector-strong -O2 -D_GNU_SOURCE
LDFLAGS = -lpthread
TARGET = scansnap

$(TARGET): scansnap.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: clean
