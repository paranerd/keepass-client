import hashlib
import struct
from Crypto.Cipher import AES

AES_BLOCK_SIZE = 16

def sha256(s):
	"""Return SHA256 digest of the string `s`."""
	return bytes(hashlib.sha256(s).digest())

def unpad(data):
	return data[:len(data) - bytearray(data)[-1]]


def pad(s):
	"""Add PKCS7 style padding"""
	n = AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE
	return s + n * struct.pack('b', n)

def aes_cbc_encrypt(data, key, enc_iv):
	"""Encrypt and return `data` with AES CBC."""
	cipher = AES.new(key, AES.MODE_CBC, enc_iv)
	return cipher.encrypt(data)

def xor(aa, bb):
	"""Return a bytearray of a bytewise XOR of `aa` and `bb`."""
	return bytearray([a ^ b for a, b in zip(bytearray(aa), bytearray(bb))])
