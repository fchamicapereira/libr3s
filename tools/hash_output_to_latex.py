#!/usr/bin/env python
#-*- coding: utf-8 -*-

import sys
import os

if len(sys.argv) < 2:
    print("Missing argument (filename)")
    sys.exit()

filepath = sys.argv[1]

if not os.path.isfile(filepath):
    print("File path {} does not exist. Exiting...".format(filepath))
    sys.exit()
    
f = open(filepath, 'r')

klatex = ''
i = 0
for line in f:
    if line == '\n': continue
    i += 1

    bb = "".join([ "\\mathtt{{0x{}}} & ".format(b) for b in line.split(' ') if b not in ['\n', ''] ])
    klatex += bb[:-2] + "\\\\ \n"

    if i == 7:
        klatex = "\\begin{{equation}}\n\\begin{{matrix}}\n{}\n\\end{{matrix}}\n\\end{{equation}}".format(klatex[:-4])
        print(klatex, "\n")
        klatex = ''
        i = 0

f.close()