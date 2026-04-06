VERSION = 0.1.0

CC = gcc
CFLAGS = -DPACKAGE_VERSION=\"$(VERSION)\" -shared -fPIC

.PHONY: all clean
all: sudo_approval.so

clean:
	-rm sudo_approval.so

sudo_approval.so: sudo_approval.c
	$(CC) $(CFLAGS) $< -o $@
