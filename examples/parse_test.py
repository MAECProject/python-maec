# MAEC Example 3 - Simple Parsing Example
# Demonstrates how to parse existing MAEC documents using
# a combination of the API and bindings

from maec.bindings import maec_bundle as bundle_binding
from maec.bundle.bundle import Bundle

# Parse the input document using the binding
binding_obj = bundle_binding.parse("zeus_anubis_maec.xml")

# Create the API Object from the parsed output
bundle_obj = Bundle.from_obj(binding_obj)

# For this example, iterate through the Action Collections
# in the input bundle, and print the ID of each Action
action_collections = bundle_obj.collections.action_collections
for action_collection in action_collections:
    for action in action_collection.action_list:
        print action.id_