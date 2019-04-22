import hashlib

def sha256(s):
	"""Return SHA256 digest of the string `s`."""
	return bytes(hashlib.sha256(s).digest())
