import argparse
import acl_aes
import tkinter
from tkinter.filedialog import askopenfilename, asksaveasfilename

class encrypterApp(tkinter.Frame):
	def __init__(self, enc_func, dec_func, kg_func, master=None):
		super().__init__(master)
		self.grid()
		self.encrypt = enc_func
		self.decrypt = dec_func
		self.keygen  = kg_func
		self.create_widgets()
	def create_widgets(self):
		self.open_Button = tkinter.Button(self)
		self.open_Button['text'] = 'Choose File'
		self.open_Button['command'] = self.open_dialog
		
		self.encrypt_Button = tkinter.Button(self)
		self.encrypt_Button['text'] = 'Encrypt'
		self.encrypt_Button['command'] = self.encrypt_dialog

		self.decrypt_Button = tkinter.Button(self)
		self.decrypt_Button['text'] = 'Decrypt'
		self.decrypt_Button['command'] = self.decrypt_dialog
		
		self.keygen_Button = tkinter.Button(self)
		self.keygen_Button['text'] = 'Generate Key'
		self.keygen_Button['command'] = self.keygen_dialog
		
		self.oldkey_Button = tkinter.Button(self)
		self.oldkey_Button['text'] = 'Load Key'
		self.oldkey_Button['command'] = self.key_dialog

		self.open_Button.grid(row=0, column=3)
		self.encrypt_Button.grid(row=2, column=0)
		self.decrypt_Button.grid(row=2, column=3)
		self.keygen_Button.grid(row=1, column=3)
		self.oldkey_Button.grid(row=1, column=2)
		
		self.input_Entry = tkinter.Entry(self)
		self.input_Entry['text'] = 'Input File'
		
		self.key_Entry   = tkinter.Entry(self)
		
		self.key_Entry.grid(row=1, column=0)
		self.input_Entry.grid(row=0, column=0)
	def open_dialog(self):
		fname = askopenfilename(title='Pick a File to Encrypt/Decrypt')
		self.input_Entry.delete(0,tkinter.END)
		self.input_Entry.insert(0,fname)
	def key_dialog(self):
		fname = askopenfilename(title='Pick a keyfile')
		self.key_Entry.delete(0, tkinter.END)
		self.key_Entry.insert(0,fname)
	def keygen_dialog(self):
		fname = asksaveasfilename(title='Save a keyfile')
		self.key_Entry.delete(0, tkinter.END)
		self.key_Entry.insert(0, fname)
		class Temp:
			def __init__(self):
				self.output = fname
				self.N = 256
		self.keygen(Temp())
	def encrypt_dialog(self):
		fname = asksaveasfilename(title='How do we save the Encrypted File?')
		key = self.key_Entry.get()
		input_file = self.input_Entry.get()
		class Temp:
			def __init__(self):
				self.output      = fname
				self.key         = key
				self.input_file  = input_file
				self.mode        = 'CTR'
		self.encrypt(Temp())
	def decrypt_dialog(self):
		fname = asksaveasfilename(title='How do we save the Decrypted File?')
		key = self.key_Entry.get()
		input_file = self.input_Entry.get()
		class Temp:
			def __init__(self):
				self.output      = fname
				self.key         = key
				self.input_file  = input_file
				self.mode        = 'CTR'
		self.decrypt(Temp())
def keygen(args):
	k = acl_aes.AESKey(length=args.N)
	k.generate()
	if args.output is None:
		k.display()
	else:
		k.write(args.output)
def encrypt(args):
	k   = acl_aes.AESKey()
	k.read(args.key)
	bc  = acl_aes.BlockCipher(key=k.key())
	with open(args.input_file, 'rb') as f:
		input_string = f.read()
	out = bc.cipher_from_string(input_string, args.mode, encrypt=True)
	if args.output is None:
		print(out)
	else:
		with open(args.output, 'wb') as f:
			f.write(out)
def decrypt(args):
	k = acl_aes.AESKey()
	k.read(args.key)
	bc = acl_aes.BlockCipher(key=k.key())
	with open(args.input_file, 'rb') as f:
		input_string = f.read()
	#input_string = bytes.fromhex(input_string)
	out = bc.cipher_from_string(input_string, args.mode, encrypt=False)
	if args.output is None:
		print(out)
	else:
		with open(args.output, 'wb') as f:
			f.write(out)
def gui(args):
	tk = tkinter.Tk()
	gui = encrypterApp(encrypt, decrypt, keygen, master=tk)
	gui.mainloop()
def parser():
	parser = argparse.ArgumentParser(description='Encrypt data using AES-128/192/256 with an implementation written for BTUs Advanced Cyber Lab')
	subparsers = parser.add_subparsers(title='Operating Modes', description='Subcommands', help='Sub-Command Help')
	kg_parser = subparsers.add_parser('keygen', help='Create an AES Key where N is 128, 192, or 256')
	kg_parser.add_argument('N', type=int, choices=[128, 192, 256], help='bits in the AES Key.')
	kg_parser.add_argument('--output', '-o', default=None, help='Output file to save the key, else print to stdout')
	kg_parser.set_defaults(func=keygen)
	en_parser = subparsers.add_parser('encrypt', help='Encrypt Data')
	en_parser.add_argument('key', help='AESKey to use for encryption.')
	en_parser.add_argument('input_file', help='Input File for Encryption/Decryption')
	en_parser.add_argument('--output', '-o', default=None, help='Output File for requested operation. Otherwise, prints to stdout')
	en_parser.add_argument('--mode', '-m', choices=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'], default='ECB', help='for Encrypt/Decrypt the chosen Mode of Operation. ECB/CBC/CFB/OFB/CTR')
	en_parser.set_defaults(func=encrypt)
	de_parser = subparsers.add_parser('decrypt', help='Decrypt Data')
	de_parser.add_argument('key', help='AESKey to use for decryption.')
	de_parser.add_argument('input_file', help='Input File for Encryption/Decryption')
	de_parser.add_argument('--output', '-o', default=None, help='Output File for requested operation. Otherwise, prints to stdout')
	de_parser.add_argument('--mode', '-m', choices=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'], default='ECB', help='for Encrypt/Decrypt the chosen Mode of Operation. ECB/CBC/CFB/OFB/CTR')
	de_parser.set_defaults(func=decrypt)
	gu_parser = subparsers.add_parser('gui', help='Start a graphical user interface.')
	gu_parser.set_defaults(func=gui)

	return parser.parse_args()
if __name__=='__main__':
	args = parser()
	args.func(args)
