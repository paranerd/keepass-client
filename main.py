from libkeepass.file import File

keepass = File("/mnt/c/Users/paranerd/Development/keepass_client/test/test.kdbx", "test")
database = keepass.open()

groups = database.get_groups()

for group in groups:
	print(group.get_title())

	for entry in group.get_entries():
		print("-> " + entry.get_title() + " (" + entry.get_raw('UUID') + ")")
		print("-> Password: " + entry.get_password())
