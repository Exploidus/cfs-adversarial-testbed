CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -Iinclude
LDFLAGS ?= -lbpf -lelf -lz

CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86

SRC = src/observer.c src/coordinator.c src/executor.c src/adversary.c src/probe_loader.c
BIN = cfs_testbed

all: bpf $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)

bpf: bpf/effect_monitor.bpf.o

bpf/effect_monitor.bpf.o: bpf/effect_monitor.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

test: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) bpf/*.o

.PHONY: all bpf test clean
