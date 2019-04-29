import struct
import hashlib
import base64
from lxml import etree, objectify
from Crypto.Cipher import Salsa20
import io
import datetime
import uuid

from . import crypto
from . import util
from .group import Group

class Database:
	def __init__(self, stream, protected_stream_key):
		self.protected_stream_key = protected_stream_key

		self.deserialize(stream)

	def deserialize(self, stream):
		# Index (4 bytes)
		index = struct.unpack('<I', stream.read(4))[0]

		# Hash (32 bytes)
		hash = struct.unpack('<32s', stream.read(32))[0] #payload.read(32)

		# Length (4 bytes)
		length = struct.unpack('<I', stream.read(4))[0] # self.stream_unpack(payload, 4, 'I')

		# Data
		data = struct.unpack('<{}s'.format(length), stream.read(length))[0] # payload.read(length)

		# Get root node
		self.root = etree.fromstring(data)

		# Objectify
		'''fileobject = io.BytesIO(data)
		self.tree = objectify.parse(fileobject)
		objectify.deannotate(self.tree, pytype=True, cleanup_namespaces=True)
		self.obj_root = self.tree.getroot()'''

		self.unprotect()

	def hash_old(self):
		stream = io.BytesIO()
		bytes = io.BytesIO(self.get())

		index = 0
		while True:
			data = bytes.read(1024 * 1024)
			if data:
				stream.write(struct.pack('<I', index))
				stream.write(hashlib.sha256(data).digest())
				stream.write(data)
				index += 1
			else:
				stream.write(struct.pack('<I', index))
				stream.write(b'\x00' * 32)
				stream.write(struct.pack('<I', 0))
				break

		return stream

	def hash(self):
		stream = bytearray()
		bytes = io.BytesIO(self.get())

		index = 0
		while True:
			data = bytes.read(1024 * 1024)
			if data:
				stream.extend(struct.pack('<I', index))
				stream.extend(hashlib.sha256(data).digest())
				stream.extend(struct.pack('<I', len(data)))
				stream.extend(data)
				index += 1
			else:
				stream.extend(struct.pack('<I', index))
				stream.extend(b'\x00' * 32)
				stream.extend(struct.pack('<I', 0))
				break

		return stream


	def serialize(self, header_hash):
		# Add header hash to Meta/HeaderHash
		#if len(self.root.xpath("/KeePassFile/Meta/HeaderHash")) < 1:
			#etree.SubElement(self.root.xpath("/KeePassFile/Meta")[0], "HeaderHash")

		#dom_header_hash = self.root.xpath("/KeePassFile/Meta/HeaderHash")[0]
		#dom_header_hash.text = header_hash

		# Protect
		self.protect()

		# Add hashed database
		return self.hash()

	def get(self, print=False):
		pp = etree.tostring(self.root, pretty_print=True, encoding='utf-8', standalone=True)

		if print:
			pp = str(pp, encoding='utf-8')

		return pp

	def get_attachment(self, id):
		attachment = self.root.xpath('/KeePassFile/Meta/Binaries/Binary[@ID={}]'.format(id))

		if len(attachment) > 0:
			return attachment[0].text
		else:
			return ""

	def _reset_salsa(self):
		"""
		Clear the salsa buffer and reset algorithm
		"""
		self._salsa_buffer = bytearray()
		iv = bytes(bytearray.fromhex('e830094b97205d2a'))
		self.salsa = Salsa20.new(crypto.sha256(self.protected_stream_key), iv)

	def _get_salsa(self, length):
		"""
		Returns the next section of the "random" Salsa20 bytes with the
		requested `length`

		@param int length
		@return string
		"""
		while length > len(self._salsa_buffer):
			new_salsa = self.salsa.encrypt(bytearray(64))
			self._salsa_buffer.extend(new_salsa)

		nacho = self._salsa_buffer[:length]
		del self._salsa_buffer[:length]
		return nacho

	def unprotect(self):
		"""
		Find all elements with a 'Protected=True' attribute and replace the text
		with an unprotected value in the XML element tree. The original text is
		set as 'ProtectedValue' attribute and the 'Protected' attribute is set
		to 'False'. The 'ProtectPassword' element in the 'Meta' section is also
		set to 'False'
		"""
		self._reset_salsa()
		self.root.xpath('.//Meta/MemoryProtection/ProtectPassword')[0].text = 'False'

		for elem in self.root.iterfind('.//Value[@Protected="True"]'):
			if elem.text is not None:
				elem.set('ProtectedValue', elem.text)
				elem.set('Protected', 'False')
				elem.text = self._unprotect(elem.text)

	def _unprotect(self, string):
		"""
		Base64 decode and XOR the given `string` with the next salsa.
		Returns an unprotected string

		@param string string
		@return string
		"""
		tmp = base64.b64decode(string.encode("utf-8"))
		return crypto.xor(tmp, self._get_salsa(len(tmp))).decode("utf-8")

	def protect(self):
		"""
		Find all elements with a 'Protected=False' attribute and replace the
		text with a protected value in the XML element tree. If there was a
		'ProtectedValue' attribute, it is deleted and the 'Protected' attribute
		is set to 'True'. The 'ProtectPassword' element in the 'Meta' section is
		also set to 'True'.

		This does not just restore the previous protected value, but reencrypts
		all text values of elements with 'Protected=False'. So you could use
		this after modifying a password, adding a completely new entry or
		deleting entry history items.
		"""
		self._reset_salsa()
		self.root.xpath('.//Meta/MemoryProtection/ProtectPassword')[0].text = 'True'

		for elem in self.root.iterfind('.//Value[@Protected="False"]'):
			if elem.text is not None:
				elem.attrib.pop('ProtectedValue', None)
				elem.set('Protected', 'True')
				elem.text = self._protect(elem.text)

	def _protect(self, string):
		"""
		XORs the given `string` with the next salsa and base64 encodes it.
		Returns a protected string.
		"""
		encoded = string.encode("utf-8")
		tmp = crypto.xor(encoded, self._get_salsa(len(encoded)))
		return base64.b64encode(tmp).decode("utf-8")

	def get_groups(self):
		"""
		Extract all groups

		@return list[Group]
		"""
		groups = []
		for dom_group in self.root.xpath('./Root/Group/Group'):
			groups.append(Group.fromxml(dom_group))

		return groups

	def add_group(self, name):
		groups = self.root.xpath('./Root/Group')[0]
		group = Group.create(name)
		groups.append(group.get_xml())

		return group.get_id()
