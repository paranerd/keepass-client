import base64
import hashlib
import uuid
import datetime

from lxml import etree

from . import util
from .attachment import Attachment

class Entry:
	def __init__(self, xml):
		"""
		Constructor

		@param ElementTree xml
		"""
		self.xml = xml

	@classmethod
	def fromxml(cls, xml):
		"""
		Parse entry from xml
		Wrapper for the constructor, acts as syntactic sugar
		to describe the purpose of this constructing method better

		@param ElementTree xml
		"""
		return cls(xml)

	@classmethod
	def create(cls, title, username=None, password=None, url=None, notes=None):
		"""
		Create new entry

		@param string title
		@param string username
		@param string password
		@param string url
		@param string notes
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
		"""
		Get the XML-representation of the entry

		@return ElementTree
		"""
		return self.xml

	def get_id(self):
		"""
		Get ID

		@return string
		"""
		return self.xml.xpath('./UUID')[0].text

	def get_title(self):
		"""
		Get title

		@return string
		"""
		return self.xml.xpath('./String[Key = "Title"]/Value')[0].text

	def get_notes(self):
		"""
		Get notes

		@return string
		"""
		return self.xml.xpath('./String[Key = "Notes"]/Value')[0].text

	def get_username(self):
		"""
		Get username

		@return string
		"""
		return self.xml.xpath('./String[Key = "Username"]/Value')[0].text

	def get_password(self):
		"""
		Get password

		@return string
		"""
		return self.xml.xpath('./String[Key = "Password"]/Value')[0].text

	def get_url(self):
		"""
		Get URL

		@return string
		"""
		return self.xml.xpath('./String[Key = "URL"]/Value')[0].text

	def get_attachments(self):
		"""
		Get attachments

		@return list[Attachment]
		"""
		attachments = []

		for attachment_xml in self.xml.xpath('./Binary'):
			attachments.append(Attachment.fromxml(attachment_xml))

		return attachments

	def add_attachment(self, filename, id):
		"""
		Add attachment

		@param string filename
		@param string id
		"""
		attachment = Attachment.create(id, filename)
		self.xml.append(attachment.get_xml())

	def remove_attachment(self, attachment):
		"""
		Remove attachment

		@param Attachment attachment
		"""

		attachment = self.xml.xpath('./Binary[Key="{}"][Value[@Ref="{}"]]'.format(attachment.get_filename(), attachment.get_id()))[0]
		attachment.getparent().remove(attachment)
