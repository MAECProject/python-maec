# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

# Compatible with MAEC v4.1

from mixbox.namespaces import Namespace, NamespaceSet, register_namespace

NS_MAEC_BUNDLE = Namespace('http://maec.mitre.org/XMLSchema/maec-bundle-4', 'maecBundle', 'http://maec.mitre.org/language/version4.1/maec_bundle_schema.xsd')
NS_MAEC_PACKAGE = Namespace('http://maec.mitre.org/XMLSchema/maec-package-2', 'maecPackage', 'http://maec.mitre.org/language/version4.1/maec_package_schema.xsd')
NS_MAEC_VOCABS = Namespace('http://maec.mitre.org/default_vocabularies-1', 'maecVocabs', 'http://maec.mitre.org/language/version4.1/maec_default_vocabularies.xsd')


MAEC_NAMESPACES = NamespaceSet()

# Magic to automatically register all Namespaces defined in this module.
for k, v in dict(globals()).items():
    if k.startswith('NS_'):
        register_namespace(v)
        MAEC_NAMESPACES.add_namespace(v)
