#MAEC Namespace Parser

#Copyright (c) 2015, The MITRE Corporation
#All rights reserved

#Compatible with MAEC v4.1
#Last updated 02/18/2014

from cybox.utils import Namespace

class Metadata(object):
    """Metadata about MAEC namespaces."""

    def __init__(self, namespace_list):
        self._ns_dict = {}
        self._prefix_dict = {}

        for ns in namespace_list:
            n = Namespace(*ns)
            self.add_namespace(n)

    def add_namespace(self, namespace):
        self._ns_dict[namespace.name] = namespace
        self._prefix_dict[namespace.prefix] = namespace

    def lookup_namespace(self, namespace):
        return self._ns_dict.get(namespace)

    def lookup_prefix(self, prefix):
        return self._prefix_dict.get(prefix)


# A list of (namespace, prefix, schemalocation) tuples
# This is loaded by the Metadata class and should not be accessed directly.
NS_LIST = [
    ('http://www.w3.org/2001/XMLSchema-instance', 'xsi', ''),
    ('http://maec.mitre.org/XMLSchema/maec-bundle-4', 'maecBundle', 'http://maec.mitre.org/language/version4.1/maec_bundle_schema.xsd'),
    ('http://maec.mitre.org/XMLSchema/maec-package-2', 'maecPackage', 'http://maec.mitre.org/language/version4.1/maec_package_schema.xsd'),
    ('http://maec.mitre.org/default_vocabularies-1', 'maecVocabs', 'http://maec.mitre.org/language/version4.1/maec_default_vocabularies.xsd')
]

maecMETA = Metadata(NS_LIST)
