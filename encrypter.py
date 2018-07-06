import argparse
import acl_aes

def keygen(args):
	print('KEYGEN')
def encrypt(args):
	print('ENCRYPT')
def decrypt(args):
	print('DECRYPT')
def parser():
	parser = argparse.ArgumentParser(description='Encrypt data using AES-128/192/256 with an implementation written for BTUs Advanced Cyber Lab')
	subparsers = parser.add_subparsers(title='Operating Modes', description='Subcommands', help='Sub-Command Help')
	kg_parser = subparsers.add_parser('keygen', help='Create an AES Key where N is 128, 192, or 256')
	kg_parser.add_argument('N', type=int, choices=[128, 192, 256], help='bits in the AES Key.')
	kg_parser.add_argument('--output', '-o', help='Output file to save the key, else print to stdout')
	kg_parser.set_defaults(func=keygen)
	en_parser = subparsers.add_parser('encrypt', help='Encrypt Data')
	en_parser.add_argument('key', help='AESKey to use for encryption.')
	en_parser.add_argument('in', help='Input File for Encryption/Decryption')
	en_parser.add_argument('--output', '-o', help='Output File for requested operation. Otherwise, prints to stdout')
	en_parser.add_argument('--mode', '-m', choices=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'], default='ECB', help='for Encrypt/Decrypt the chosen Mode of Operation. ECB/CBC/CFB/OFB/CTR')
	en_parser.set_defaults(func=encrypt)
	de_parser = subparsers.add_parser('decrypt', help='Decrypt Data')
	de_parser.add_argument('key', help='AESKey to use for decryption.')
	de_parser.add_argument('in', help='Input File for Encryption/Decryption')
	de_parser.add_argument('--output', '-o', help='Output File for requested operation. Otherwise, prints to stdout')
	de_parser.add_argument('--mode', '-m', choices=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'], default='ECB', help='for Encrypt/Decrypt the chosen Mode of Operation. ECB/CBC/CFB/OFB/CTR')
	de_parser.set_defaults(func=decrypt)

	return parser.parse_args()
if __name__=='__main__':
	args = parser()
	args.func(args)
