import struct
import hashlib
import base64
from lxml import etree
from Crypto.Cipher import Salsa20

from . import crypto
from . import util
from .group import Group

class Database:
	def __init__(self, stream, protected_stream_key):
		self.protected_stream_key = protected_stream_key

		# Index (4 bytes)
		index = struct.unpack('<I', stream.read(4))[0]

		# Hash (32 bytes)
		hash = struct.unpack('<32s', stream.read(32))[0] #payload.read(32)

		# Length (4 bytes)
		length = struct.unpack('<I', stream.read(4))[0] # self.stream_unpack(payload, 4, 'I')

		# Data
		data = struct.unpack('<{}s'.format(length), stream.read(length))[0] # payload.read(length)

		#print(data.decode('utf-8'))

		self.root = etree.fromstring(data)
		#self.tree = objectify.parse(payload)
		#objectify.deannotate(self.tree, pytype=True, cleanup_namespaces=True)
		#self.obj_root = self.tree.getroot()

		self.unprotect()

		#print(etree.tostring(self.root))

	def unprotect(self):
		"""
		Find all elements with a 'Protected=True' attribute and replace the text
		with an unprotected value in the XML element tree. The original text is
		set as 'ProtectedValue' attribute and the 'Protected' attribute is set
		to 'False'. The 'ProtectPassword' element in the 'Meta' section is also
		set to 'False'.
		"""
		self._reset_salsa()
		#self.obj_root.Meta.MemoryProtection.ProtectPassword._setText('False')
		for elem in self.root.iterfind('.//Value[@Protected="True"]'):
			if elem.text is not None:
				elem.set('ProtectedValue', elem.text)
				elem.set('Protected', 'False')
				unprotected_text = self._unprotect(elem.text)
				print("unprotecting: " + elem.text + " -> " + unprotected_text)
				elem.text = unprotected_text

	def _reset_salsa(self):
		"""Clear the salsa buffer and reset algorithm."""
		self._salsa_buffer = bytearray()
		iv = bytes(bytearray.fromhex('e830094b97205d2a'))
		self.salsa = Salsa20.new(crypto.sha256(self.protected_stream_key), iv)

	def _get_salsa(self, length):
		"""
		Returns the next section of the "random" Salsa20 bytes with the
		requested `length`.
		"""
		while length > len(self._salsa_buffer):
			new_salsa = self.salsa.encrypt(bytearray(64))
			self._salsa_buffer.extend(new_salsa)
		nacho = self._salsa_buffer[:length]
		del self._salsa_buffer[:length]
		return nacho

	def _unprotect(self, string):
		"""
		Base64 decode and XOR the given `string` with the next salsa.
		Returns an unprotected string.
		"""
		tmp = base64.b64decode(string.encode("utf-8"))
		return util.xor(tmp, self._get_salsa(len(tmp))).decode("utf-8")

	def get_groups(self):
		groups = []
		for dom_group in self.root.xpath('./Root/Group/Group'):
			groups.append(Group(dom_group, self.protected_stream_key))

		return groups
