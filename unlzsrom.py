# REFERENCES:
# https://gist.github.com/w4kfu/3a9772156901e5717ec7
# https://github.com/alguien-gh/scripts/blob/master/exploits/rom0x/rom0x.sh
# http://reverseengineering.stackexchange.com/questions/3662/backup-from-zynos-but-can-not-be-decompressed-with-lzs

# The only way available to decompress the specific rom file was online with routerpwn.com/zynos/ i think that they are
# using the c program linked bellow under the hood for decompression; I wrote this because i myself was looking for
# a pure pythonic way to decompress the rom file; After a days of searching the internet for such solution i didn't find
# any working one, But my search was not useless and eventually i managed to came with my this solution.

# THIS WILL NOT WORK ON "ALL" ROMS; BUT YOU CAN ALWAYS LINK PYTHON AND 
# https://github.com/alguien-gh/scripts/blob/master/exploits/rom0x/unlzs.c OR JUST COMPILE THE THIS
# --------------------
# python unlzsrom.py rom-0
# 52574267
# TP-LINK
# public
# public
# public

import sys
import re

# Lempel-Ziv-Stac (LZS) decompression
# Implementation found in sciw.exe
 
class LZSBitReader:
	def __init__(self, bytes):
		self.bytes = bytes
		self.gen = self.generator(bytes)
 
	def generator(self, bts):
		for b in bts:
			bi = ord(b)
			for i in xrange(8):
				yield int((bi >> (7 - i)) & 1)
 
	def getBit(self):
		return next(self.gen)
 
	def getBits(self, num):
		res = 0
		for i in xrange(0, num):
			res += self.getBit() << num - 1 - i
		return res
		 
	def getLen(self):
		length = 2
		while True:
			bits = self.getBits(2)
			length += bits
			if bits != 3 or length >= 8:
				break
		if length == 8:
			while True:
				bits = self.getBits(4)
				length += bits
				if bits != 15:
					break
		return length
 
def LZSDecompress(data):
	out = ""
	reader = LZSBitReader(data)
	while True:
		if reader.getBit() == 0:			# Uncompressed byte
			out += chr(reader.getBits(8))
		else:
			if reader.getBit() == 1:		# 7-bit offset
				offset = reader.getBits(7)
				if offset == 0:			 # End Of Stream
					break
			else:
				offset = reader.getBits(11) # 11-bit offset
			length = reader.getLen()
			if offset > len(out):
				raise ValueError("[LZS]: Dictionary underflow")
			for i in xrange(0, length):	 # dic
				out += out[-offset]
	return out

def dataspot(fname):
		fpos=8568
		fend=8788
		fhandle=file(fname)
		fhandle.seek(fpos)
		chunk=""
		amount=221
		while fpos < fend:
			if fend-fpos < amount:
				amount = fend-fpos
				chunk = fhandle.read(amount)
				fpos += len(chunk)
				return chunk

ret = LZSDecompress(dataspot(sys.argv[1]))
for m in re.finditer("([\x20-\x7f]{4,})[\n\0]", ret):
	print m.group(1)
