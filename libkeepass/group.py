from .entry import Entry

class Group:
	def __init__(self, dom, protected_stream_key):
		self.dom = dom
		self.protected_stream_key = protected_stream_key

	def get_title(self):
		return self.dom.find("Name").text

	def get_entries(self):
		entries = []

		for dom_entry in self.dom.xpath('./Entry'):
			entries.append(Entry(dom_entry, self.protected_stream_key))

		return entries

	def get_subgroup(self):
		return Group(self.dom.xpath('./Group'))
