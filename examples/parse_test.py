from maec.bindings import maec_bundle as bundle_binding
from maec.bundle.bundle import Bundle

binding_obj = bundle_binding.parse("zeus_anubis_maec.xml")
bundle_obj = Bundle.from_obj(binding_obj)

action_collections = bundle_obj.collections.action_collections
for action_collection in action_collections:
    for action in action_collection.action_list:
        print action.implementation