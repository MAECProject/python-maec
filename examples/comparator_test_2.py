import pprint
import maec.bindings.maec_bundle as maec_bundle_binding
from maec.bundle.bundle import Bundle
# Matching properties dictionary
match_on = {'FileObjectType': ['file_name'],
            'WindowsRegistryKeyObjectType': ['key'],
            'WindowsMutexObjectType': ['name']}

bundle1 = Bundle.from_obj(maec_bundle_binding.parse("zeus_anubis_maec.xml"))
bundle2 = Bundle.from_obj(maec_bundle_binding.parse("zeus_threatexpert_maec.xml"))

comparator = Bundle.compare([bundle1, bundle2], match_on)

print "******Common Objects:*******\n"
pprint.pprint(comparator.get_common())
print "****************************"
print "******Unique Objects:*******\n"
pprint.pprint(comparator.get_unique())
print "****************************"
