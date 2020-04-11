CC=g++ -Wall -fPIC

DIR=$(shell pwd)
SRC=$(DIR)/src
BUILD=$(DIR)/build
BIN=$(DIR)/bin
EX=$(DIR)/examples

Z3_DIR=$(VIGOR_DIR)/z3
LIB_FLAGS=-lz3 -Wl,-rpath,$(Z3_DIR)/lib -L$(Z3_DIR)/lib -I$(Z3_DIR)/build/include

LIB_RSSKS=$(BUILD)/lib
LIB_RSSKS_INCLUDE=$(BUILD)/include
LIB_RSSKS_FLAGS=-lrssks -Wl,-rpath,$(LIB_RSSKS) -L$(LIB_RSSKS) -I$(LIB_RSSKS_INCLUDE)

all: build

debug: CC += -D DEBUG
debug: build

build: $(LIB_RSSKS)/librssks.so

install: build
	sudo cp $(LIB_RSSKS)/librssks.so /usr/lib
	sudo chmod 0755 /usr/lib/librssks.so
	sudo cp $(LIB_RSSKS_INCLUDE)/*.h /usr/include
	sudo ldconfig

uninstall:
	sudo rm /usr/lib/librssks.so
	sudo ldconfig

$(LIB_RSSKS)/librssks.so: $(BUILD)/hash.o $(BUILD)/config.o $(BUILD)/util.o $(BUILD)/solver.o
	@mkdir -p $(BUILD) $(LIB_RSSKS) $(LIB_RSSKS_INCLUDE)
	$(CC) -shared -o $(LIB_RSSKS)/librssks.so $(BUILD)/solver.o $(BUILD)/config.o $(BUILD)/hash.o $(BUILD)/util.o $(LIB_FLAGS)
	@cp $(SRC)/rssks.h $(LIB_RSSKS_INCLUDE)/rssks.h

examples: $(LIB_RSSKS)/librssks.so
	$(MAKE) -C $(EX)

solver: $(BUILD)/solver.o
$(BUILD)/solver.o: $(SRC)/solver.c $(SRC)/solver.h $(SRC)/util.h $(SRC)/hash.h $(SRC)/rssks.h
	@mkdir -p $(BUILD)
	$(CC) -c $(SRC)/solver.c -o $(BUILD)/solver.o $(LIB_FLAGS)

hash: $(BUILD)/hash.o
$(BUILD)/hash.o: $(SRC)/hash.c $(SRC)/hash.h $(SRC)/util.h $(SRC)/rssks.h
	@mkdir -p $(BUILD)
	$(CC) -c $(SRC)/hash.c -o $(BUILD)/hash.o $(LIB_FLAGS)

config: $(BUILD)/config.o
$(BUILD)/config.o: $(SRC)/config.c $(SRC)/util.h $(SRC)/rssks.h
	@mkdir -p $(BUILD)
	$(CC) -c $(SRC)/config.c -o $(BUILD)/config.o $(LIB_FLAGS)

util: $(BUILD)/util.o
$(BUILD)/util.o: $(SRC)/util.c
	@mkdir -p $(BUILD)
	$(CC) -c $(SRC)/util.c -o $(BUILD)/util.o

clean:
	rm -rf $(BUILD) $(BIN) *.o *~ main find_k* proof* unsat-core* check_k*
	$(MAKE) -C $(EX) clean

.PHONY: run examples