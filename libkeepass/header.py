import struct

class Header:
	fields = {
		'end_of_header': 0,
		'comment': 1,
		# cipher used for the data stream after the header
		'cipher_id': 2,
		# indicates whether decrypted data stream is gzip compressed
		'compression_flags': 3,
		#
		'master_seed': 4,
		#
		'transform_seed': 5,
		#
		'transform_rounds': 6,
		#
		'encryption_iv': 7,
		# key used to protect data in xml
		'protected_stream_key': 8,
		# first 32 bytes of the decrypted data stream after the header
		'stream_start_bytes': 9,
		# cipher used to protect data in xml (ARC4 or Salsa20)
		'inner_random_stream_id': 10,
	}

	fmt = {
		3: '<I',
		6: '<q',
		10: '<I'
	}

	data = {}
	data_raw = {}

	def __init__(self, stream):
		self.deserialize(stream)

	def deserialize(self, stream):
		while True:
			# Get ID
			field_id = struct.unpack('b', stream.read(1))[0]

			# Get length
			field_length = struct.unpack('h', stream.read(2))[0]

			# Get data
			field_data = struct.unpack('<' + str(field_length) + 's', stream.read(field_length))[0]

			self.set(field_id, field_data)

			# End of header
			if field_id == 0:
				break

	def serialize(self):
		# Serialize header to stream
		header = bytearray()

		field_ids = list(self.data.keys())
		field_ids.sort()
		# field_id 0 must be last
		field_ids.append(field_ids.pop(0))

		for field_id in field_ids:
			value = self.data_raw[field_id]
			length = len(value)
			header.extend(struct.pack('<b', field_id))
			header.extend(struct.pack('<h', length))
			header.extend(struct.pack('{}s'.format(length), value))

		return header

	def get(self, key, raw=False):
		# Convert string key to int if necessary
		key = key if isinstance(key, int) else self.fields[key]

		if raw:
			return self.data_raw[key]
		else:
			return self.data[key]

	def set(self, key, val):
		# Convert string key to int if necessary
		key = key if isinstance(key, int) else self.fields[key]

		self.data_raw[key] = val

		if key in self.fmt:
			val = self.convert(self.fmt[key], val)

		self.data[key] = val

	def convert(self, type, bytes):
		return struct.unpack(type, bytes)[0]
