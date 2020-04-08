CC=g++ -Wall
Z3_DIR=$(VIGOR_DIR)/z3

DIR=$(shell pwd)
BUILD=$(DIR)/../build

LIB_FLAGS=-lz3 -Wl,-rpath,$(Z3_DIR)/lib -L$(Z3_DIR)/lib -I$(Z3_DIR)/build/include

LIB_RSSKS=$(BUILD)/lib
LIB_RSSKS_INCLUDE=$(BUILD)/include
LIB_RSSKS_FLAGS=-lrssks -Wl,-rpath,$(LIB_RSSKS) -L$(LIB_RSSKS) -I$(LIB_RSSKS_INCLUDE)

SRCS=$(wildcard *.c)
EXEC=$(patsubst %.c,%,$(SRCS))

all: $(EXEC)

$(EXEC): %: %.c
	$(CC) -o $@ $< $(LIB_FLAGS) $(LIB_RSSKS_FLAGS)

.PHONY: clean
clean:
	rm -f $(EXEC)