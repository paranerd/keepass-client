from lxml import etree

def dict_to_xml(name, data):
	node = etree.Element(name)

	for key, value in data.items():
		if isinstance(value, list):
			for entry in value:
				subnode = dict_to_xml(key, entry)
				node.append(subnode)
			continue
		elif isinstance(value, dict):
			subnode = dict_to_xml(key, value)
		else:
			subnode = etree.Element(key)

			if value:
				subnode.text = str(value)

		node.append(subnode)

	return node

	def dict_to_xml_attr(name, data):
		node = etree.Element(name)

		for key, value in data.items():
			if isinstance(value, list):
				for entry in value:
					subnode = dict_to_xml(key, entry)
					node.append(subnode)
				continue
			#elif is
			elif isinstance(value, dict):
				subnode = dict_to_xml(key, value)
			else:
				subnode = etree.Element(key)

				if value:
					subnode.text = str(value)

			node.append(subnode)

		return node
