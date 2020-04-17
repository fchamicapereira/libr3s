#!/usr/bin/env python
#-*- coding: utf-8 -*-

# Test data including the secret key, ip, port numbers and the hash values 
# as the result is from "Intel Ethernet Controller 710 Series Datasheet".

import random

KEY=[]

def reset_key():
	global KEY
	KEY = [
		0xa0, 0x62, 0xa0, 0x62, 0xa0, 0x62, 0xa0, 0x62, 
		0xa0, 0x62, 0xa0, 0x62, 0xa0, 0x62, 0xa0, 0x63, 
		0xe0, 0xf6, 0x2b, 0x8c, 0x79, 0x7f, 0x00, 0x00, 
		0x00, 0x62, 0x9a, 0x97, 0x9a, 0x18, 0x42, 0x61, 
		0x50, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0xe8, 0xc9, 0xae, 0xc4, 0x3b, 0x56, 0x00, 0x00, 
		0x38, 0xb5, 0x4b, 0x8c
	]

def left_most_32bits_of_key():
	return (KEY[0] << 24) | (KEY[1] << 16) | (KEY[2] << 8) | KEY[3]

def shift_key():
	bitstr = ''
	for k in KEY:
	   bitstr += bin(k)[2:].zfill(8)
	shifted = bitstr[1:]
	shifted += bitstr[0]
	for i, k in enumerate(KEY):
		KEY[i] = int(shifted[:8], 2)
		shifted = shifted[8:]

def compute_hash(input_bytes):
	reset_key()
	result = 0;
	bitstr = ''
	for b in input_bytes:
		bitstr += bin(b)[2:].zfill(8) # eliminate prefix "0b" and fill zeros to fit into 8 bits
	for b in bitstr:
		if b == '1':
			result ^= left_most_32bits_of_key()
		shift_key()
	return result

def get_ip_number(ip):
	ipnum = ip.split('.')
	return int(ipnum[0]) << 24 | int(ipnum[1]) << 16 | int(ipnum[2]) << 8 | int(ipnum[3])

def get_input(srcip, dstip, srcport, dstport, protocol):
	input_bytes = []
	input_bytes.append((srcip & 0xff000000) >> 24)
	input_bytes.append((srcip & 0x00ff0000) >> 16)
	input_bytes.append((srcip & 0x0000ff00) >> 8)
	input_bytes.append(srcip & 0x000000ff)
	input_bytes.append((dstip & 0xff000000) >> 24)
	input_bytes.append((dstip & 0x00ff0000) >> 16)
	input_bytes.append((dstip & 0x0000ff00) >> 8)
	input_bytes.append(dstip & 0x000000ff)
	input_bytes.append((srcport & 0xff00) >> 8)
	input_bytes.append(srcport & 0x00ff)
	input_bytes.append((dstport & 0xff00) >> 8)
	input_bytes.append(dstport & 0x00ff)
	input_bytes.append(protocol & 0xff)
	return input_bytes

srcip = get_ip_number('67.149.41.77')
dstip = get_ip_number('46.147.49.70')
srcport = 32077
dstport = 3658
protocol = 17

n_procs = 4
load = [0] * n_procs
computed = 0

hash1 = compute_hash(get_input(srcip, dstip, srcport, dstport, protocol))
hash2 = compute_hash(get_input(dstip, srcip, dstport, srcport, protocol))

print("hash {}".format(hex(hash1)))
print("hash {}".format(hex(hash2)))

