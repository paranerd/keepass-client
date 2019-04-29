import base64
import hashlib
import uuid
import datetime

from . import util
from .attachment import Attachment

class Entry:
	def __init__(self, xml):
		self.xml = xml

	@classmethod
	def fromxml(cls, xml):
		"""
		Parse entry from xml
		Wrapper for the constructor, acts as syntactic sugar
		to describe the purpose of this constructing method better
		"""
		return cls(xml)

	@classmethod
	def create(cls, title, username=None, password=None, url=None, notes=None):
		"""
		Create new entry
		"""
		id = base64.b64encode(uuid.uuid1().bytes).decode('utf-8')
		now = datetime.datetime.utcnow().isoformat()

		entry = {
			'UUID': id,
			'IconID': 0,
			'ForegroundColor': None,
			'BackgroundColor': None,
			'OverrideURL': None,
			'Tags': None,
			'Times': {
				'CreationTime': now,
				'LastModificationTime': now,
				'LastAccessTime': now,
				'ExpiryTime': now,
				'Expires': 'False',
				'UsageCount': 1,
				'LocationChanged': now
			},
			'String': [
				{
					'Key': 'Notes',
					'Value': None,
				},
				{
					'Key': 'Title',
					'Value': title,
				},
				{
					'Key': 'UserName',
					'Value': username,
				},
				{
					'Key': 'Password',
					'Value': password,
				},
				{
					'Key': 'URL',
					'Value': url,
				}
			],
			'AutoType': {
				'Enabled': 'True',
				'DataTransferObfuscation': 0
			},
			'History': None
		}

		xml = util.dict_to_xml("Entry", entry)
		xml.xpath('./String[Key = "Password"]/Value')[0].set('Protected', 'False')

		return cls(xml)

	def get_xml(self):
		return self.xml

	def get_id(self):
		return self.xml.xpath('./UUID')[0].text

	def get_title(self):
		return self.xml.xpath('./String[Key = "Title"]/Value')[0].text

	def get_notes(self):
		return self.xml.xpath('./String[Key = "Notes"]/Value')[0].text

	def get_username(self):
		return self.xml.xpath('./String[Key = "Username"]/Value')[0].text

	def get_password(self):
		return self.xml.xpath('./String[Key = "Password"]/Value')[0]

	def get_url(self):
		return self.xml.xpath('./String[Key = "URL"]/Value')[0].text

	def get_attachments(self):
		attachments = []

		for attachment in self.xml.xpath('./Binary'):
			id = attachment.xpath('./Value/@Ref')[0]
			filename = attachment.find('Key').text
			attachments.append(Attachment(id, filename))

		return attachments
