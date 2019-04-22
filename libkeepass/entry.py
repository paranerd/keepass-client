import base64
import hashlib
from Crypto.Cipher import Salsa20

class Entry:
	def __init__(self, dom, protected_stream_key):
		self.dom = dom
		self.protected_stream_key = protected_stream_key

	def get_title(self):
		return self.dom.xpath('./String[Key = "Title"]/Value')[0].text

	def get_notes(self):
		return self.dom.xpath('./String[Key = "Notes"]/Value')[0].text

	def get_password(self):
		elem = self.dom.xpath('./String[Key = "Password"]/Value')[0]
		return elem.text

	def get_raw(self, node_name):
		return self.dom.xpath('./' + node_name)[0].text
