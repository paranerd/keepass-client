import hashlib
import struct
from Crypto.Cipher import AES

AES_BLOCK_SIZE = 16

def sha256(s):
	"""
	Return SHA256 digest of a string

	@param string s
	@return bytes
	"""
	return bytes(hashlib.sha256(s).digest())

def pad(s):
	"""
	Add PKCS5 padding

	@param bytes s
	@return bytes
	"""
	n = AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE
	return s + n * struct.pack('b', n)

def unpad(s):
	"""
	Remove PKCS5 padding

	@param bytes s
	@return bytes
	"""
	return s[:-ord(s[-1:])]

def aes_cbc_encrypt(data, key, enc_iv):
	"""
	Encrypt data using AES in CBC mode

	@param bytes data
	@param bytes key
	@param bytes enc_iv
	@return bytes
	"""
	cipher = AES.new(key, AES.MODE_CBC, enc_iv)
	return cipher.encrypt(data)

def xor(aa, bb):
	"""
	Return a bytearray of a bytewise XOR

	@param bytes aa
	@param bytes bb
	@return bytearray
	"""
	return bytearray([a ^ b for a, b in zip(bytearray(aa), bytearray(bb))])
