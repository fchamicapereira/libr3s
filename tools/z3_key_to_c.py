#!/usr/bin/python3

import sys

if len(sys.argv) < 2:
    print("Usage: ./z3_key_to_c.py \"{key}\"")
    sys.exit(1)

k = sys.argv[1]

k_bytes = [ k[2:][i:i+2] for i in range(0, len(k[2:]), 2) ]
code = "R3S_key_t k = {"

for i, b in enumerate(k_bytes):
    if i % 8 == 0: code += "\n\t"
    code += "0x{}".format(b)
    if i < len(k_bytes) - 1: code += ", "

code += "\n};"
print(code)