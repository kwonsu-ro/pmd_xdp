CC=gcc
CFLAGS=-g -Wall -O2
LDFLAGS=-lyara -lxdp -lbpf -lpthread -lz

SRCS=src/main.c src/xdp_util.c src/yara_scan.c src/xdp_loader.c
OBJS=$(SRCS:.c=.o)
BIN_FW=pmd_xdp
TARGET=src/$(BIN_FW)

BPF_CLANG=clang

KERN_DIR=/lib/modules/$(shell uname -r)/build
BPF_PATH=./xdp_prog_kern.o
BPF_OBJ=src/$(BPF_PATH)
BPF_SRC=src/xdp_prog_kern.c

all: $(TARGET) $(BPF_OBJ)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) -O2 -g -Wall -target bpf -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN_FW) $(TARGET) $(BPF_OBJ) $(BPF_PATH)

install:
	cp -dpr $(TARGET) ./$(BIN_FW)
	cp -dpr $(BPF_OBJ) ./$(BPF_PATH)
