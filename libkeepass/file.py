# https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45
# https://github.com/lphooge/libKeePHPass/blob/master/KdbHeader.php
# https://github.com/libkeepass/libkeepass/blob/master/libkeepass/kdb4.py -> cipher IDs

import os
from Crypto.Cipher import AES
import struct
import io
import base64

from . import crypto
from .header import Header
from .database import Database

KDB4_SIGNATURE = (0x9AA2D903, 0xB54BFB67)

class File:
	block_size = 16
	path = ""
	passphrase = ""
	master_key = None
	database = None

	def __init__(self, path, passphrase):
		self.path = path
		self.passphrase = passphrase

	def open(self):
		encrypted = ""

		with open(self.path, "rb") as f_in:
			# Extract signature (2x 4 bytes)
			self.signature = struct.unpack('<II', f_in.read(8))

			if self.signature != KDB4_SIGNATURE:
				raise Exception("Signature does not match")

			# Extract version (2x 2 bytes) -> (minor, major)
			self.version = struct.unpack('<hh', f_in.read(4))

			# Extract header
			self.header = Header(f_in)

			self.header.write()

			# Extract encrypted database
			encrypted = f_in.read()

		# Generate master key
		self.master_key = self.generate_master_key()

		# Decrypt database
		decrypted = self.decrypt(encrypted)

		# Extract database
		self.database = Database(io.BytesIO(decrypted), self.header.get('protected_stream_key'))

		return self.database

	def save(self):
		outpath = os.path.join(os.path.dirname(self.path), 'out.kdbx')

		with open(outpath, 'wb') as out:
			# Write header
			header = self.header.serialize()
			out.write(header)

			# Get header hash
			hash = base64.b64encode(crypto.sha256(header))

			# Write database
			database = self.database.write(self.header, hash, self.master_key, iv)
			out.write(database)

	def generate_master_key(self):
		# Generate composite key
		composite_key = crypto.sha256(crypto.sha256(self.passphrase.encode('utf-8')))

		# Init cipher
		cipher = AES.new(self.header.get('transform_seed'), AES.MODE_ECB)

		# Init transformed key
		transformed_key = composite_key

		for x in range(0, self.header.get('transform_rounds')):
			transformed_key = cipher.encrypt(transformed_key)

		# Hash transformed key
		transformed_key = crypto.sha256(transformed_key)

		# Concat master seed to transformed key
		transformed_key = self.header.get('master_seed') + transformed_key

		# Hash again
		self.master_key = crypto.sha256(transformed_key)

		return self.master_key

	def decrypt(self, encrypted):
		cipher = AES.new(self.master_key, AES.MODE_CBC, self.header.get('encryption_iv'))
		decrypted = self.unpad(cipher.decrypt(encrypted))

		# Check decryption
		if decrypted[:len(self.header.get('stream_start_bytes'))] == self.header.get('stream_start_bytes'):
			return decrypted[len(self.header.get('stream_start_bytes')):]
		else:
			raise Exception("Decryption failed")

	def pad(self, s):
		return s + (self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)

	def unpad(self, s):
		return s[:-ord(s[len(s)-1:])]

	def stream_unpack(self, bytes, length, type):
		return struct.unpack('<' + type, bytes.read(length))[0]
