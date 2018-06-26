import secrets
from ctypes import c_ubyte

class AESCipher:
	def __init__(self):
		self.length  = 128
		self.K       = [c_ubyte(0)]*self.length
		self.Nb      = {128:4, 192:4, 256:4}
		self.Nk      = {128:4, 192:6, 256:8}
		self.Nr      = {128:10, 192:12, 256:14}
		self.inverse = False
	def Rcon(self, i):
		if i == 0:
			return c_ubyte(0x8d)
		else:
			return c_ubyte((self.Rcon(i-1)<<1)^(0x11b & -(self.Rcon(i-1)>>7)))
	def fieldmultiply(self, a, b):
		p = c_ubyte(0)

		while a.value > 0 and b.value > 0:
			if b.value & 1:
				p = c_ubyte(p.value^a.value)
			b = c_ubyte(b.value>>1)
			a = c_ubyte(self.xtime(a.value))
		return p.value
	def xtime(self, i):
		b = c_ubyte(i)
		xor = c_ubyte(0x1b&-(b.value>>7))
		return c_ubyte((b.value<<1)^xor.value).value
	def sbox(self, x, y):
		pass

	def KeyExpansion(self):
		temp = [c_ubyte(0)]*4
		w    = [c_ubyte(0)]*(self.Nb*(self.Nr+1))
		for i in range(self.Nk):
			w[i] = [self.K[4*i], self.K[4*i+1], self.K[4*i+2], self.K[4*i+3]]
		for i in range(self.Nk, 
	def AddRoundKey(self):
		pass
	def MixColumns(self, state):
		pass
	def ShiftRows(self, state):
		pass
	def SubBytes(self, state):
		pass
	def SubWord(self, wrd):
		pass
	def RotWord(self, wrd):
		pass
	def Cipher(self, _in, w):
		## Input:
		##	_in: input, and array of bytes of length 4*self.Nb
		##	w:   The Key Schedule, array of bytes size self.Nb*(self.Nr+1)
		state = [[c_ubyte(0)]*self.Nb]*4
		
		which_row    = 0
		which_column = 0
		for byte in _in:
			state[which_row%4][which_column] = byte
			which_row+=1
			if which_row%4 = 0:
				which_column+=1
		
		state = self.AddRoundKey(state, w[self.Nr*self.Nb:(self.Nr+1)*self.Nb])
		for r in range(1, self.Nr):
			state = self.SubBytes(state)
			state = self.ShiftRows(state)
			state = self.MixColumns(state)
			state = self.AddRoundKey(state, w[self.Nr*self.Nb:(self.Nr+1)*self.Nb])
		state = self.SubBytes(state)
		state = self.ShiftRows(state)
		state = self.AddRoundKey(state, w[self.Nr*self.Nb:(self.Nr+1)*self.Nb])
		
		out = [0]*(4*self.Nb)
		which_row    = 0
		which_column = 0
		which_byte   = 0
		while which_byte < self.Nb*4:
			out[which_byte] = state[which_row%4][which_column]
			which_row+=1
			if which_row%4 == 0:
				which_column+=1
			which_byte+=1
		return out
class BlockCipher:
	def __init__(self):
		self.mode = 'ECB'		
