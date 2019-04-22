def xor(aa, bb):
	"""Return a bytearray of a bytewise XOR of `aa` and `bb`."""
	return bytearray([a ^ b for a, b in zip(bytearray(aa), bytearray(bb))])
