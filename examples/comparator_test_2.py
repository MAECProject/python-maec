import pprint
import maec.bindings.maec_bundle as maec_bundle_binding
from maec.bundle.bundle import Bundle

bundle1 = Bundle.from_obj(maec_bundle_binding.parse("zeus_anubis_maec.xml"))
bundle2 = Bundle.from_obj(maec_bundle_binding.parse("zeus_threatexpert_maec.xml"))

comparator = Bundle.compare([bundle1, bundle2])
pprint.pprint(comparator.get_common())
pprint.pprint(comparator.get_unique())

