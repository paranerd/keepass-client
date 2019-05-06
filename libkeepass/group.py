import base64
import uuid
import datetime

from . import util
from .entry import Entry

class Group:
	def __init__(self, xml):
		self.xml = xml

	@classmethod
	def fromxml(cls, xml):
		"""
		Parse group from xml
		Wrapper for the constructor, acts as syntactic sugar
		to describe the purpose of this constructing method better
		"""
		return cls(xml)

	@classmethod
	def create(cls, name):
		"""
		Create new entry
		"""
		id = base64.b64encode(uuid.uuid1().bytes).decode('utf-8')
		now = datetime.datetime.utcnow().isoformat()

		# Build group dict
		group = {
			'UUID': id,
			'Name': name,
			'Notes': None,
			'IconID': 48,
			'Times': {
				'CreationTime': now,
				'LastModificationTime': now,
				'LastAccessTime': now,
				'ExpiryTime': now,
				'Expires': 'False',
				'UsageCount': 2,
				'LocationChanged': now
			},
			'IsExpanded': 'True',
			'DefaultAutoTypeSequence': None,
			'EnableAutoType': None,
			'EnableSearching': None,
			'LastTopVisibleEntry': None
		}

		# Convert dict to XML
		xml = util.dict_to_xml("Group", group)

		return cls(xml)

	def get_id(self):
		return self.xml.xpath('./UUID')[0].text

	def get_xml(self):
		return self.xml

	def get_title(self):
		return self.xml.find("Name").text

	def get_entries(self):
		entries = []

		for entry_xml in self.xml.xpath('./Entry'):
			entries.append(Entry.fromxml(entry_xml))

		return entries

	def get_subgroup(self):
		return Group(self.xml.xpath('./Group'))

	def add_entry(self, title, username=None, password=None, url=None):
		entry = Entry.create(title, username, password, url)
		self.xml.append(entry.get_xml())

		return entry.get_id()
