import os

from .file import File

file = None
database = None

def open(path, passphrase):
	global file
	global database
	file = File(path, passphrase)
	database = file.open()

def get_database():
	return database.get(True)

def get_all_groups():
	return database.get_groups()

def add_group(name):
	return database.add_group(name)

def add_attachment(entry, path):
	if not os.path.isfile(path):
		raise Exception("File does not exist")

	with open(path, 'rb') as file:
		filename = os.path.basename(path)
		content = file.read()

		# Add attachment to database
		ref_id = database.add_attachment(content)

		# Add attachment to entry node
		entry.add_attachment(filename, ref_id)

def remove_attachment(entry, attachment):
	# Remove attachment from database
	database.remove_attachment(attachment)

	# Remove attachment from entry node
	entry.remove_attachment(attachment)

def save(path=None):
	file.save(path)
