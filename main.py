import os
import sys
import getopt
import signal

from libkeepass.file import File

class Keepass_Client:
	active_group = None

	def __init__(self, path):
		self.path = path
		self.passphrase = "test" #input("Passphrase: ")
		self.keepass = File(path, self.passphrase)
		self.database = self.keepass.open()

	def show_menu_main(self):
		while True:
			print()
			print("--- Main Menu ---")
			print("[1] Groups")
			print("[P] Print database")
			print("[S] Save database")
			print("[B] Quit")

			selection = input("Select: ")
			print()

			if selection.lower() == 'q':
				sys.exit()
			elif selection.lower() == 'p':
				print(self.database.get(True))
			elif selection.lower() == 's':
				path = os.path.join(os.path.dirname(self.path), 'out.kdbx')
				self.keepass.save(path)
			elif selection.isdigit() and selection == '1':
				self.show_menu_groups()
				break
			else:
				print("Invalid input")

			print()

	def show_menu_groups(self):
		groups = self.database.get_groups()

		while True:
			print("--- Groups ---")

			for idx, group in enumerate(groups):
				print("[{idx}] {title}".format(idx = idx + 1, title = group.get_title()))

			print("[A] Add Group")
			print("[B] Main Menu")
			selection = input("Select: ")
			print()

			if selection.lower() == 'b':
				self.show_menu_main()
				break
			elif selection.lower() == 'a':
				name = input("Name: ")
				self.database.add_group(name)
				self.show_menu_groups()
				break
			elif selection.isdigit() and int(selection) <= len(groups):
				self.active_group = groups[int(selection) - 1]
				self.show_menu_entries()
				break
			else:
				print("Invalid input")

	def show_menu_entries(self):
		group = self.active_group
		entries = group.get_entries()

		while True:
			print()
			print("--- {title} ---".format(title = group.get_title()))

			for idx, entry in enumerate(entries):
				print("[{idx}] {title}".format(idx = idx + 1, title = entry.get_title()))

			print("[A] Add Entry")
			print("[B] Groups")
			selection = input("Select: ")
			print()

			if selection.lower() == 'b':
				self.show_menu_groups()
				break
			elif selection.lower() == 'a':
				title = input("Title: ")
				password = input("Password: ")
				group.add_entry(title, None, password)
				self.show_menu_entries()
				break
			elif selection.isdigit() and int(selection) <= len(entries):
				self.show_entry(entries[int(selection) - 1])
				break
			else:
				print("Invalid input")

	def show_entry(self, entry):
		print()
		print("--- {title} ---".format(title = entry.get_title()))
		print("Title: " + entry.get_title())
		print("Password: " + entry.get_password())

		attachments = entry.get_attachments()

		for attachment in attachments:
			print("Attachment: {} [{}]".format(attachment.get_filename(), attachment.get_id()))

		self.show_menu_entries()

def signal_handler(sig, frame):
	print('Quit.')
	sys.exit(0)

if __name__ == "__main__":
	# Catch Ctrl+C
	signal.signal(signal.SIGINT, signal_handler)

	try:
		opts, args = getopt.getopt(sys.argv[1:], "d:",["database="])
	except getopt.GetoptError:
		print('main.py -d <database>')
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-h':
			print('main.py -d <database>')
			sys.exit()
		elif opt in ("-d", "--database"):
			kc = Keepass_Client(arg)
			kc.show_menu_main()
