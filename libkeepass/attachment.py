from . import util

class Attachment:
	def __init__(self, xml):
		self.xml = xml

	@classmethod
	def fromxml(cls, xml):
		return cls(xml)

	@classmethod
	def create(cls, id, filename):
		attachment = {
			'Key': filename,
			'Value': ""
		}

		xml = util.dict_to_xml("Binary", attachment)
		xml.xpath('./Value')[0].set('Ref', id)

		return cls(xml)

	def get_id(self):
		return self.xml.xpath('./Value/@Ref')[0]

	def get_filename(self):
		return self.xml.find('Key').text

	def get_xml(self):
		return self.xml
