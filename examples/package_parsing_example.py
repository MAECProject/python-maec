# MAEC Example 2 - Simple Parsing Example
# Demonstrates how to parse existing MAEC documents the parse_xml_instance() method
# Uses the MAEC Package created by the package_generation_example as input

import maec

# Parse the input document using the parse_xml_instance() method
maec_objects = maec.parse_xml_instance("sample_maec_package.xml")

# Get the Package Object from the parsed input
maec_package = maec_objects['api']

# For this example, iterate through the Malware Subjects
# in the input Package, and print the ID of each
for malware_subject in maec_package.malware_subjects:
    print malware_subject.id_