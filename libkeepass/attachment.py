class Attachment:
	def __init__(self, id, filename):
		self.id = id
		self.filename = filename

	def get_id(self):
		return self.id

	def get_filename(self):
		return self.filename
