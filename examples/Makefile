CC=g++ -Wall
Z3_DIR=$(VIGOR_DIR)/z3

DIR=$(shell pwd)
BUILD=$(DIR)/../build
BIN=$(DIR)/../bin

LIB_FLAGS=-lz3 -Wl,-rpath,$(Z3_DIR)/lib -L$(Z3_DIR)/lib -I$(Z3_DIR)/build/include

LIB_R3S=$(BUILD)/lib
LIB_R3S_INCLUDE=$(BUILD)/include
LIB_R3S_FLAGS=-lr3s -Wl,-rpath,$(LIB_R3S) -L$(LIB_R3S) -I$(LIB_R3S_INCLUDE)

SRCS=$(wildcard *.c)
EXEC=$(patsubst %.c,%,$(SRCS))

all: $(EXEC)

$(EXEC): %: %.c
	@mkdir -p $(BIN)
	$(CC) -o $(BIN)/$@ $< $(LIB_FLAGS) $(LIB_R3S_FLAGS)

.PHONY: clean
clean:
	rm -rf $(BIN) $(EXEC)