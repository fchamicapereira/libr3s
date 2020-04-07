CC=g++
Z3_DIR=$(VIGOR_DIR)/z3
LIB_FLAGS=-lz3 -L$(Z3_DIR)/lib/ -I$(Z3_DIR)/build/include/
CFLAGS=-Wall

all: main

run: main
	@./main

debug: CFLAGS += -D DEBUG
debug: run

main: solver.o hash.o main.o util.o
	$(CC) -o main main.o solver.o hash.o util.o $(CFLAGS) $(LIB_FLAGS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS) $(LIB_FLAGS)

solver.o: solver.c solver.h util.h hash.h rssks.h
	$(CC) -c solver.c $(CFLAGS) $(LIB_FLAGS)

hash.o: hash.c hash.h rssks.h
	$(CC) -c hash.c $(CFLAGS) $(LIB_FLAGS)

util.o: util.c
	$(CC) -c util.c $(CFLAGS)

clean:
	rm -f *.o *~ main find_k* proof* unsat-core* check_k*

.PHONY: run