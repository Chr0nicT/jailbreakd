TARGET  = jailbreakd
SRC     = $(wildcard *.c) $(wildcard *.m) $(wildcard */*.c) $(wildcard */*.m)

CC      = xcrun -sdk iphoneos gcc -arch arm64 -arch arm64e
LDID    = ldid
CHMOD   = chmod
CFLAGS  = -I. -I./helpers -I./kernel_call -I./mach -framework Foundation -framework IOKit

.PHONY: all install clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^
	$(LDID) -SEnt.plist $@
	$(CHMOD) 755 $@


clean:
	rm jailbreakd