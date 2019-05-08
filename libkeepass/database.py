import struct
import hashlib
import base64
from lxml import etree, objectify
from Crypto.Cipher import Salsa20
import io
import datetime
import uuid
import re

from . import crypto
from . import util
from .group import Group

class Database:
	def __init__(self, stream, protected_stream_key):
		"""
		Constructor

		@param bytes stream
		@param string protected_stream_key
		"""
		self.protected_stream_key = protected_stream_key

		self.deserialize(stream)

	def deserialize(self, stream):
		"""
		Get database XML from bytes
		Read bytes first, then unprotect values

		@param bytes stream
		"""
		# Index (4 bytes)
		index = struct.unpack('<I', stream.read(4))[0]

		# Hash (32 bytes)
		hash = struct.unpack('<32s', stream.read(32))[0]

		# Length (4 bytes)
		length = struct.unpack('<I', stream.read(4))[0]

		# Data
		data = struct.unpack('<{}s'.format(length), stream.read(length))[0]

		# Get root node
		parser = etree.XMLParser(remove_blank_text=True)
		self.root = etree.fromstring(data, parser=parser)

		self.unprotect()

	def hash(self):
		"""
		Convert database XML to hashed blocks as bytes

		@return bytearray
		"""
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
		"""
		Get database as bytes
		Protect values first, then convert XML to hashed blocks

		@param string header_hash
		@return bytearray
		"""
		# Add header hash to Meta/HeaderHash
		if len(self.root.xpath("/KeePassFile/Meta/HeaderHash")) < 1:
			etree.SubElement(self.root.xpath("/KeePassFile/Meta")[0], "HeaderHash")

		dom_header_hash = self.root.xpath("/KeePassFile/Meta/HeaderHash")[0]
		dom_header_hash.text = header_hash

		# Protect
		self.protect()

		# Return database as hashed blocks
		return self.hash()

	def get(self, print=False):
		"""
		Return pretty printed database
		"""
		if print:
			pp = etree.tostring(self.root, pretty_print=True, encoding='utf-8', standalone=True)
			pp = str(pp, encoding='utf-8')
		else:
			pp = etree.tostring(self.root, encoding='utf-8', standalone=True)

		return pp

	def get_next_attachment_id(self):
		"""
		Get next attachment ID

		@return string
		"""
		next_id = 0

		ids = self.root.xpath("/KeePassFile/Meta/Binaries/Binary/@ID")

		for id in ids:
			if int(id) > next_id:
				next_id = int(id)

		return str(next_id + 1)

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
				# Remember protected value
				elem.set('ProtectedValue', elem.text)

				# Set protected attribute to false
				elem.set('Protected', 'False')

				# Base64-decode protected value
				decoded = base64.b64decode(elem.text.encode("utf-8"))

				# Decrypt value
				decrypted = crypto.xor(decoded, self._get_salsa(len(decoded))).decode("utf-8")

				# Set value
				elem.text = decrypted

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
				# Remove protected value attribute
				elem.attrib.pop('ProtectedValue', None)

				# Set protected to true
				elem.set('Protected', 'True')

				# Encrypt value
				value_utf8 = elem.text.encode("utf-8")
				encrypted = crypto.xor(value_utf8, self._get_salsa(len(value_utf8)))

				# Base64-encode encrypted value
				encoded = base64.b64encode(encrypted).decode("utf-8")

				# Set value
				elem.text = encoded

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
		"""
		Add new group

		@param string name
		@return int
		"""
		groups = self.root.xpath('./Root/Group')[0]
		group = Group.create(name)
		groups.append(group.get_xml())

		return group.get_id()

	def get_attachment(self, id):
		"""
		Get attachment content

		@param string id
		@return string
		"""
		attachment = self.root.xpath('/KeePassFile/Meta/Binaries/Binary[@ID={}]'.format(id))

		if len(attachment) > 0:
			return attachment[0].text
		else:
			return ""

	def add_attachment(self, content):
		"""
		Add attachment to database

		@param bytes content
		@return string
		"""
		# Encode content
		encoded = base64.b64encode(content).decode("utf-8")

		# Get attachments parent node
		node_binaries = self.root.xpath("/KeePassFile/Meta/Binaries")[0]

		# Check if content exists
		exists = node_binaries.xpath("./Binary[text()=\"{}\"]".format(encoded))

		if len(exists):
			# Attachment already exists, just get the reference ID
			next_id = exists[0].get('ID')
		else:
			# Attachment does not exist yet, create it
			next_id = self.get_next_attachment_id()

			# Create attachment node
			binary = etree.Element("Binary")
			binary.set("ID", next_id)
			binary.text = encoded

			# Add attachment to database
			node_binaries.append(binary)

		return next_id

	def remove_attachment(self, attachment):
		"""
		Remove attachment

		@param Attachment attachment
		"""
		# Is the attachment used anywhere else?
		used = self.root.xpath('//Binary/Value[@Ref="{}"]'.format(attachment.get_id()))

		if len(used) == 1:
			# Remove attachment from database
			node_binary = self.root.xpath('/KeePassFile/Meta/Binaries/Binary[@ID="{}"]'.format(attachment.get_id()))[0]
			node_binary.getparent().remove(node_binary)
