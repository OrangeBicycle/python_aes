import secrets
import io
from ctypes import c_ubyte

class AESKey:
	def __init__(self):
		self.length = 128
		self.byte_length = int(self.length/8)
		self.K = [c_ubyte(0)]*self.byte_length
	def generate(self):
		self.K = [c_ubyte(secrets.randbits(8)) for i in range(int(128/8))]
	def display(self):
		for bit in self.K:
			print('%d ' % bit.value)
	def write(self, f):
		with open(f, 'w') as output:
			output.write('ACLAES:', (bit.value for bit in self.K))
	def key(self):
		return self.K
class AESCipher:
	def __init__(self, key=None):
		self.length  = 128
		self.K       = [c_ubyte(0)]*self.length if key==None else key
		self.Nb      = {128:4, 192:4, 256:4}
		self.Nk      = {128:4, 192:6, 256:8}
		self.Nr      = {128:10, 192:12, 256:14}
		self.inverse = False
	def Rcon(self, i):
		if i == 0:
			return c_ubyte(0x8d)
		else:
			return c_ubyte((self.Rcon(i-1).value<<1)^(0x11b & -(self.Rcon(i-1).value>>7)))
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
	def sbox(self, b):
		if self.inverse == False:
			return [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
			0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
			0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
			0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
			0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
			0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
			0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
			0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
			0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
			0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
			0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
			0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
			0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
			0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
			0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
			0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16][b]
		else:
			return [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
			0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
			0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
			0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
			0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
			0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
			0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
			0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
			0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
			0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
			0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
			0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
			0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
			0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
			0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D][b]
	def KeyExpansion(self):
		flag = self.inverse
		self.inverse = False
		temp = [c_ubyte(0), c_ubyte(0), c_ubyte(0), c_ubyte(0)]
		w    = [c_ubyte(0)]*(self.Nb[self.length]*(self.Nr[self.length]+1))
		for i in range(self.Nk[self.length]):
			w[i] = [self.K[4*i], self.K[4*i+1], self.K[4*i+2], self.K[4*i+3]]
		for i in range(self.Nk[self.length], self.Nb[self.length]*(self.Nr[self.length]+1)):
			temp = w[i-1]
			print('i=%d temp=' % i)
			self.printword(temp)
			if i%self.Nk[self.length] == 0:
				print('RotWord(temp)=')
				self.printword(self.RotWord(temp))
				temp = self.SubWord(self.RotWord(temp))
				print('SubWord(RotWord(temp))=')
				self.printword(temp)
				temp[0] = c_ubyte(temp[0].value^self.Rcon(i/self.Nk[self.length]).value)
				print('RCon^temp=')
				self.printword(temp)
			elif self.Nk[self.length] > 6 and i%self.Nk[self.length] == 4:
				temp = self.SubWord(temp)
			w[i] = [c_ubyte(w[i-self.Nk[self.length]][0].value^temp[0].value),
				c_ubyte(w[i-self.Nk[self.length]][1].value^temp[1].value),
				c_ubyte(w[i-self.Nk[self.length]][2].value^temp[2].value),
				c_ubyte(w[i-self.Nk[self.length]][3].value^temp[3].value)]
		self.inverse = flag
		'''
		if self.inverse:
			dw = [c_ubyte(0)]*(self.Nb[self.length]*(self.Nr[self.length]+1))
			for i in range((self.Nr[self.length]+1)*self.Nb[self.length]):
				dw[i] = w[i]
			for r in range(1, self.Nr[self.length]):
				dw[r*self.Nb[self.length]:(r+1)*self.Nb[self.length]] = self.MixColumns(dw[r*self.Nb[self.length]:(r+1)*self.Nb[self.length]])
			return dw
		else:
			return w
		#self.inverse = flag
		'''
		return w
	def printword(self, w):
		print('{0} {1} {2} {3}'.format(hex(w[0].value), hex(w[1].value), hex(w[2].value), hex(w[3].value)))
	def AddRoundKey(self, state, w):
		state_prime = state#[[c_ubyte(0)]*self.Nb[self.length]]*4
		print('ROUND KEY')
		self.printstate(w)
		for i in range(self.Nb[self.length]):
			state_prime[0][i] = c_ubyte(state[0][i].value^w[i][0].value)	
			state_prime[1][i] = c_ubyte(state[1][i].value^w[i][1].value)	
			state_prime[2][i] = c_ubyte(state[2][i].value^w[i][2].value)	
			state_prime[3][i] = c_ubyte(state[3][i].value^w[i][3].value)
		return state_prime	
	def MixColumns(self, state):
		state_prime = state #[[c_ubyte(0)]*self.Nb[self.length]]*4
		if self.inverse == False:
			c3, c2, c1, c0 = (c_ubyte(0x03), c_ubyte(0x01), c_ubyte(0x01), c_ubyte(0x02))
		else:
			c3, c2, c1, c0 = (c_ubyte(0x0b), c_ubyte(0x0d), c_ubyte(0x09), c_ubyte(0x0e)) 
		for col in range(self.Nb[self.length]):
			state_prime[0][col], state_prime[1][col], state_prime[2][col], state_prime[3][col] = (
			c_ubyte(self.fieldmultiply(c0, state[0][col])^self.fieldmultiply(c3, state[1][col])^self.fieldmultiply(c2, state[2][col])^self.fieldmultiply(c1, state[3][col])),
			c_ubyte(self.fieldmultiply(c1, state[0][col])^self.fieldmultiply(c0, state[1][col])^self.fieldmultiply(c3, state[2][col])^self.fieldmultiply(c2, state[3][col])),
			c_ubyte(self.fieldmultiply(c2, state[0][col])^self.fieldmultiply(c1, state[1][col])^self.fieldmultiply(c0, state[2][col])^self.fieldmultiply(c3, state[3][col])),
			c_ubyte(self.fieldmultiply(c3, state[0][col])^self.fieldmultiply(c2, state[1][col])^self.fieldmultiply(c1, state[2][col])^self.fieldmultiply(c0, state[3][col])))
		return state_prime
	def ShiftRows(self, state):
		state_prime = state#[[c_ubyte(0)]*self.Nb[self.length]]*4
		for x in range(4):
			if self.inverse == False:
				state_prime[x] = state[x][x:]+state[x][:x]
			else:
				state_prime[x] = state[x][-1*x:]+state[x][:-1*x]
		return state_prime
	def SubBytes(self, state):
		state_prime = state #[[c_ubyte(0)]*self.Nb[self.length]]*4
		for x in range(4):
			for y in range(self.Nb[self.length]):
				state_prime[x][y] = c_ubyte(self.sbox(state[x][y].value))
		return state_prime
	def SubWord(self, wrd):
		return [c_ubyte(self.sbox(wrd[i].value)) for i in range(4)]
	def RotWord(self, wrd):
		return [wrd[1], wrd[2], wrd[3], wrd[0]]
	def Cipher(self, _in):
		## Input:
		##	_in: input, and array of bytes of length 4*self.Nb[self.length]
		##	w:   The Key Schedule, array of bytes size self.Nb[self.length]*(self.Nr[self.length]+1)
		state = [[c_ubyte(0)]*self.Nb[self.length]]*4
		self.printstate(state)
		w = self.KeyExpansion()
		print('W:')
		for entry in w:
			self.printword(entry)
		for i in range(4):
			state[i] = [_in[i], _in[i+4], _in[i+(2*4)], _in[i+(3*4)]]
		print('BEGIN')
		self.printstate(state)
		
		if self.inverse:
			step = -1
			rnge = (self.Nr[self.length]-1, 0)
			state = self.AddRoundKey(state, w[self.Nr[self.length]*self.Nb[self.length]:(self.Nr[self.length]+1)*self.Nb[self.length]])
		else:
			step = 1
			rnge = (1, self.Nr[self.length])
			state = self.AddRoundKey(state, w[0:self.Nb[self.length]])
		print('AddRoundKey %d' % 0)
		self.printstate(state)
		for r in range(rnge[0], rnge[1], step):
			if self.inverse:
				state = self.ShiftRows(state)
				print('SHIFTROWS %d' % r)
				self.printstate(state)
				state = self.SubBytes(state)
				print('SUBBYTES %d' % r)
				self.printstate(state)
				state = self.AddRoundKey(state, w[r*self.Nb[self.length]:(r+1)*self.Nb[self.length]])
				print('ADDROUNDKEY %d' % r)
				self.printstate(state)
				state = self.MixColumns(state)
				print('MIXCOLUMNS %d' % r)
				self.printstate(state)
			else:
				state = self.SubBytes(state)
				print('SUBBYTES %d' % r)
				self.printstate(state)
				state = self.ShiftRows(state)
				print('SHIFTROWS %d' % r)
				self.printstate(state)
				state = self.MixColumns(state)
				print('MIXCOLUMNS %d' % r)
				self.printstate(state)
				state = self.AddRoundKey(state, w[r*self.Nb[self.length]:(r+1)*self.Nb[self.length]])
				print('ADDROUNDKEY %d' % r)
				self.printstate(state)
		if self.inverse:
			state = self.ShiftRows(state)
			state = self.SubBytes(state)
			state = self.AddRoundKey(state, w[0:self.Nb[self.length]])
		else:
			state = self.SubBytes(state)
			print('SUBBYTES FINAL')
			self.printstate(state)
			state = self.ShiftRows(state)	
			print('SHIFTROWS FINAL')
			self.printstate(state)
			state = self.AddRoundKey(state, w[self.Nr[self.length]*self.Nb[self.length]:(self.Nr[self.length]+1)*self.Nb[self.length]])		
		print('ADDROUNDKEY FINAL')
		self.printstate(state)
		'''
		out = [0]*(4*self.Nb[self.length])
		which_row    = 0
		which_column = 0
		which_byte   = 0
		while which_byte < self.Nb[self.length]*4:
			out[which_byte] = state[which_row%4][which_column]
			which_row+=1
			if which_row%4 == 0:
				which_column+=1
			which_byte+=1
		return out
		'''
		out = [0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0]
		for i in range(4):
			for j in range(4):
				out[i+(4*j)] = state[i][j]
		return out
	def printstate(self, state):
		for i in range(self.Nb[self.length]):
			print('{0} {1} {2} {3}'.format(hex(state[i][0].value), hex(state[i][1].value), hex(state[i][2].value), hex(state[i][3].value)))
			print('----------------')
class BlockCipher:
	def __init__(self, key=None):
		self.mode = 'ECB'
		self.aes  = AESCipher(key=key)
	def ecb(self, m, encrypt=True):
		_in = []
		for c in m:
			_in.append(c_ubyte(ord(c)))
			print('orig {0} ord {1} chr {2} hex {3}'.format(c, ord(c), chr(ord(c)), hex(ord(c))))
		if len(_in)%16 != 0:
			_in = _in+[c_ubyte(0)]*(16-(len(_in)%16))
		blocks = int(len(_in)/16)
		self.aes.inverse = False if encrypt else True
		print('AES INVERSE %s' % self.aes.inverse)
		_out = []
		for i in range(blocks):
			_out.extend(self.aes.Cipher(_in[16*i:16*(i+1)]))
		_chr = []
		for c in _out:
			_chr.append(chr(c.value))
		return _chr
	def cbc(self, m, encrypt=True):
		_in = []
		for c in m:
			_in.append(c_ubyte(ord(c)))
			print('orig {0} ord {1} chr {2} hex {3}'.format(c, ord(c), chr(ord(c)), hex(ord(c))))
		if len(_in)%16 != 0:
			_in = _in+[c_ubyte(0)]*(16-(len(_in)%16))
		blocks = int(len(_in)/16)
		self.aes.inverse = False if encrypt else True
		print('AES INVERSE %s' % self.aes.inverse)
		#Junk First block implying no IV
		if encrypt:
			_in = [c_ubyte(secrets.randbits(8)) for i in range(16)] + _in
			blocks += 1
		iv  = [c_ubyte(secrets.randbits(8)) for i in range(16)]
		
		_out = []
		_chr = []
		
		prev = iv
		for i in range(blocks):
			temp = _in[16*i:16*(i+1)]
			if encrypt:
				xor_block = [c_ubyte(a.value^b.value) for a,b in zip(prev, temp)]
				prev = self.aes.Cipher(xor_block)
				_out.extend(prev)
			else:
				c_out = self.aes.Cipher(temp)
				_out.extend([c_ubyte(a.value^b.value) for a,b in zip(prev, c_out)])
				prev = temp
		if encrypt == False:
			_out = _out[16:]
		for c in _out:
			_chr.append(chr(c.value))
		return _chr
	def cfb(self, m, encrypt=True):
		_in = []
		for c in m:
			_in.append(c_ubyte(ord(c)))
			print('orig {0} ord {1} chr {2} hex {3}'.format(c, ord(c), chr(ord(c)), hex(ord(c))))
		if len(_in)%16 != 0:
			_in = _in+[c_ubyte(0)]*(16-(len(_in)%16))
		blocks = int(len(_in)/16)
		#self.aes.inverse = False if encrypt else True
		#print('AES INVERSE %s' % self.aes.inverse)
		if encrypt:
			iv  = [c_ubyte(secrets.randbits(8)) for i in range(16)]
		else:
			iv = _in[0:16]
			_in = _in[16:]
		_out = []
		_chr = []

		prev = iv
		for i in range(blocks):
			temp=_in[16*i:16*(i+1)]
			if encrypt:
				c_block = self.aes.Cipher(prev)
				prev = [c_ubyte(a.value^b.value) for a,b in zip(temp, c_block)]
				_out.extend(prev)
			else:
				c_block = self.aes.Cipher(prev)
				_out.extend([c_ubyte(a.value^b.value) for a,b in zip(temp, c_block)])
				prev = temp
		if encrypt:
			_out = iv+_out
		for c in _out:
			_chr.append(chr(c.value))
		return _chr
	def ofb(self, m, encrypt=True):
		_in = []
		for c in m:
			_in.append(c_ubyte(ord(c)))
			print('orig {0} ord {1} chr {2} hex {3}'.format(c, ord(c), chr(ord(c)), hex(ord(c))))
		if len(_in)%16 != 0:
			_in = _in+[c_ubyte(0)]*(16-(len(_in)%16))
		blocks = int(len(_in)/16)
		#self.aes.inverse = False if encrypt else True
		#print('AES INVERSE %s' % self.aes.inverse)
		if encrypt:
			iv  = [c_ubyte(secrets.randbits(8)) for i in range(16)]
		else:
			iv = _in[0:16]
			_in = _in[16:]
		_out = []
		_chr = []

		prev = iv
		for i in range(blocks):
			temp =_in[16*i:16*(i+1)]
			prev = self.aes.Cipher(prev)
			_out.extend([c_ubyte(a.value^b.value) for a,b in zip(temp, prev)])
		if encrypt:
			_out = iv+_out
		for c in _out:
			_chr.append(chr(c.value))
		return _chr
	def ctr(self, m, encrypt=True):
		_in = []
		for c in m:
			_in.append(c_ubyte(ord(c)))
			print('orig {0} ord {1} chr {2} hex {3}'.format(c, ord(c), chr(ord(c)), hex(ord(c))))
		if len(_in)%16 != 0:
			_in = _in+[c_ubyte(0)]*(16-(len(_in)%16))
		blocks = int(len(_in)/16)
		if encrypt:
			iv  = [c_ubyte(secrets.randbits(8)) for i in range(16)]
		else:
			iv = _in[0:16]
			_in = _in[16:]
		
		ctr = 0	
		_out = []
		_chr = []
	def build_bytearray(self, number):
		
if __name__=='__main__':
	k = AESKey()
	k.generate()
	k.display()
	'''
	k.K = [c_ubyte(0x2b), c_ubyte(0x7e), c_ubyte(0x15), c_ubyte(0x16), c_ubyte(0x28), c_ubyte(0xae), c_ubyte(0xd2), c_ubyte(0xa6),
		c_ubyte(0xab), c_ubyte(0xf7), c_ubyte(0x15), c_ubyte(0x88), c_ubyte(0x09), c_ubyte(0xcf), c_ubyte(0x4f), c_ubyte(0x3c)]
	bc = BlockCipher(key=k.key())
	ori = [c_ubyte(0x32), c_ubyte(0x43), c_ubyte(0xf6), c_ubyte(0xa8), c_ubyte(0x88), cs_ubyte(0x5a), c_ubyte(0x30), c_ubyte(0x8d),
		c_ubyte(0x31), c_ubyte(0x31), c_ubyte(0x98), c_ubyte(0xa2), c_ubyte(0xe0), c_ubyte(0x37), c_ubyte(0x07), c_ubyte(0x34)]
	'''
	'''
	k.K = [c_ubyte(0x00), c_ubyte(0x01), c_ubyte(0x02), c_ubyte(0x03), c_ubyte(0x04), c_ubyte(0x05), c_ubyte(0x06), c_ubyte(0x07),
		c_ubyte(0x08), c_ubyte(0x09), c_ubyte(0x0a), c_ubyte(0x0b), c_ubyte(0x0c), c_ubyte(0x0d), c_ubyte(0x0e), c_ubyte(0x0f)]
	bc = BlockCipher(key=k.key())
	ori = [c_ubyte(0x00), c_ubyte(0x11), c_ubyte(0x22), c_ubyte(0x33), c_ubyte(0x44), c_ubyte(0x55), c_ubyte(0x66), c_ubyte(0x77),
		c_ubyte(0x88), c_ubyte(0x99), c_ubyte(0xaa), c_ubyte(0xbb), c_ubyte(0xcc), c_ubyte(0xdd), c_ubyte(0xee), c_ubyte(0xff)]
	for i in range(len(ori)):
		ori[i] = chr(ori[i].value)
	'''
	ori = '0102030405060708090a0b0c0d0e0f'
	bc = BlockCipher(key=k.key())
	ciphertext = bc.ecb(ori, encrypt=True)
	plaintext = bc.ecb(ciphertext, encrypt=False)
	print('Ciphertext ECB: %s' % ciphertext)
	print('Plaintext ECB: %s' % plaintext)
	
	ciphertext = bc.cbc(ori, encrypt=True)
	plaintext = bc.cbc(ciphertext, encrypt=False)
	print('Ciphertext CBC: %s' % ciphertext)
	print('Plaintext CBC: %s' % plaintext)
	
	ciphertext = bc.cfb(ori, encrypt=True)
	plaintext = bc.cfb(ciphertext, encrypt=False)
	print('Ciphertext CFB: %s' % ciphertext)
	print('Plaintext CFB: %s' % plaintext)
	
	ciphertext = bc.ofb(ori, encrypt=True)
	plaintext = bc.ofb(ciphertext, encrypt=False)
	print('Ciphertext OFB: %s' % ciphertext)
	print('Plaintext OFB: %s' % plaintext)
