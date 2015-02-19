import pprint
import maec.bindings.maec_bundle as maec_bundle_binding
from maec.bundle import Bundle
# Matching properties dictionary
match_on_dictionary = {'FileObjectType': ['file_name'],
                       'WindowsRegistryKeyObjectType': ['hive', 'values.name/data'],
                       'WindowsMutexObjectType': ['name']}
# Parse in the input Bundle documents and create their python-maec Bundle class representations
bundle1 = Bundle.from_obj(maec_bundle_binding.parse("zeus_threatexpert_maec.xml"))
bundle2 = Bundle.from_obj(maec_bundle_binding.parse("zeus_anubis_maec.xml"))
# Perform the comparison and get the results
comparison_results = Bundle.compare([bundle1, bundle2], match_on = match_on_dictionary, case_sensitive = False)
# Pretty print the common and unique Objects
print "******Common Objects:*******\n"
pprint.pprint(comparison_results.get_common())
print "****************************"
print "******Unique Objects:*******\n"
pprint.pprint(comparison_results.get_unique())
print "****************************"
