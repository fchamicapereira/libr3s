CC=g++ -Wall -fPIC
Z3_DIR=$(VIGOR_DIR)/z3
LIB_FLAGS=-lz3 -Wl,-rpath,$(Z3_DIR/lib) -L$(Z3_DIR)/lib -I$(Z3_DIR)/build/include

DIR=$(shell pwd)
SRC=$(DIR)/src
BUILD=$(DIR)/build
BIN=$(DIR)/bin
EX=$(DIR)/examples

LIB_RSSKS=$(BUILD)/lib
LIB_RSSKS_INCLUDE=$(BUILD)/include

LIB_RSSKS_FLAGS=-lrssks -Wl,-rpath,$(LIB_RSSKS) -L$(LIB_RSSKS) -I$(LIB_RSSKS_INCLUDE)

all: main

run: main
	@./main

debug: CFLAGS += -D DEBUG
debug: run

#main: solver.o hash.o main.o util.o
#	$(CC) -o main main.o solver.o hash.o util.o $(CFLAGS) $(LIB_FLAGS)

#main.o: main.c
#	$(CC) -c main.c $(CFLAGS) $(LIB_FLAGS)

build: hash.o util.o
	@mkdir -p $(BUILD) $(LIB_RSSKS) $(LIB_RSSKS_INCLUDE)
	$(CC) -shared -o $(LIB_RSSKS)/librssks.so $(BUILD)/hash.o $(BUILD)/util.o
	@cp $(SRC)/rssks.h $(LIB_RSSKS_INCLUDE)/rssks.h

examples: build
	@mkdir -p $(BIN)
	$(CC) $(EX)/X710hash.c -o $(BIN)/X710hash $(LIB_FLAGS) $(LIB_RSSKS_FLAGS)

solver.o: $(SRC)/solver.c $(SRC)/solver.h $(SRC)/util.h $(SRC)/hash.h $(SRC)/rssks.h
	@mkdir -p $(BUILD)
	$(CC) -c $(SRC)/solver.c -o $(BUILD)/solver.o $(LIB_FLAGS)

hash.o: $(SRC)/hash.c $(SRC)/hash.h $(SRC)/util.h $(SRC)/rssks.h
	@mkdir -p $(BUILD)
	$(CC) -c $(SRC)/hash.c -o $(BUILD)/hash.o $(LIB_FLAGS)

util.o: $(SRC)/util.c
	@mkdir -p $(BUILD)
	$(CC) -c $(SRC)/util.c -o $(BUILD)/util.o

clean:
	rm -rf $(BUILD) $(BIN) *.o *~ main find_k* proof* unsat-core* check_k*

.PHONY: run