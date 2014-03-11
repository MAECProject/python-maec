# Fuzzy string matching test script
# Runs the fuzzy comparator module against a MAEC Package

import maec
import sys

objects = maec.parse_xml_instance(sys.argv[1], check_version=False)
api_obj = objects['api']
object_properties = {}
# List of comparison results as lists
comparison_results = []
# Chains of relationships between more than two properties
chains = []

# Get all of the properties of the objects in the document
for malware_subject in api_obj.malware_subjects:
    if malware_subject.findings_bundles.bundles:
        for bundle in malware_subject.findings_bundles.bundles:
            bundle.fuzzy_compare()