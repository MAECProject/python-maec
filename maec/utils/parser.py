# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import maec
from lxml import etree

class UnsupportedVersionError(Exception):
    pass

class UnknownVersionError(Exception):
    pass

class UnsupportedRootElement(Exception):
    pass

class EntityParser(object):
    def __init__(self):
        self.is_bundle = False
        self.is_package = False

    def _check_version(self, tree):
        '''Returns true of the instance document @tree is a version supported by python-maec'''

        try:
            root = tree.getroot() # is tree an lxml.Element or lxml.ElementTree
        except AttributeError:
            root = tree

        if not root.attrib.get('schema_version'):
            raise UnknownVersionError("No version attribute set on xml instance. Unable to determine version compatibility")

        python_maec_version = maec.__version__ # ex: '4.1.0.0'
        supported_maec_version = ('4.1', '2.1') # ex: '4.1.0'
        document_version = root.attrib['schema_version']

        if document_version not in supported_maec_version:
            raise UnsupportedVersionError("Your python-maec library supports MAEC %s, or the MAEC Bundle Schema at %s and MAEC Package Schema at %s. Document version was %s" % (supported_maec_version[0], supported_maec_version[0], supported_maec_version[1], document_version))

        return True

    def _check_root(self, tree):
        try:
            root = tree.getroot() # is tree an lxml.Element or lxml.ElementTree
        except AttributeError:
            root = tree
        # General compatibility check
        if root.tag not in ("{http://maec.mitre.org/XMLSchema/maec-bundle-4}MAEC_Bundle", "{http://maec.mitre.org/XMLSchema/maec-package-2}MAEC_Package"):
            raise UnsupportedRootElement("Document root element must be an instance of MAEC_Package or MAEC_Bundle")

        # Determine if we're dealing with a MAEC Bundle or MAEC Package
        if "MAEC_Bundle" in root.tag:
            self.is_bundle = True
        elif "MAEC_Package" in root.tag:
            self.is_package = True

        return True

    def _apply_input_namespaces(self, tree, entity):
        try:
            root = tree.getroot() # is tree an lxml.Element or lxml.ElementTree
        except AttributeError:
            root = tree
        
        entity.__input_namespaces__ = dict(root.nsmap.iteritems())

    def parse_xml_to_obj(self, xml_file, check_version=True):
        """Creates a MAEC binding object from the supplied xml file.

        Arguments:
        xml_file -- A filename/path or a file-like object reprenting a MAEC instance document
        check_version -- Inspect the version before parsing.
        """
        parser = etree.ETCompatXMLParser(huge_tree=True, resolve_entities=False)
        tree = etree.parse(xml_file, parser=parser)

        # Check the root and determine the type of document we're dealing with
        self._check_root(tree)

        if check_version:
            self._check_version(tree)

        binding_obj = None
        if self.is_package:
            import maec.bindings.maec_package as maec_package_binding
            binding_obj = maec_package_binding.PackageType().factory()
            binding_obj.build(tree.getroot())
        elif self.is_bundle:
            import maec.bindings.maec_bundle as maec_bundle_binding
            binding_obj = maec_bundle_binding.BundleType().factory()
            binding_obj.build(tree.getroot())

        return binding_obj

    def parse_xml(self, xml_file, check_version=True):
        """Creates a python-maec Bundle or Package object from the supplied xml_file.

        Arguments:
        xml_file -- A filename/path or a file-like object reprenting a MAEC instance (i.e. Package or Bundle) document
        check_version -- Inspect the version before parsing.
        """
        parser = etree.ETCompatXMLParser(huge_tree=True, resolve_entities=False)
        tree = etree.parse(xml_file, parser=parser)

        api_obj = None
        binding_obj = self.parse_xml_to_obj(xml_file, check_version)
        if self.is_package:
            from maec.package.package import Package # resolve circular dependencies
            api_obj = Package.from_obj(binding_obj)
        elif self.is_bundle:
            from maec.bundle.bundle import Bundle # resolve circular dependencies
            api_obj = Bundle.from_obj(binding_obj)
        self._apply_input_namespaces(tree, api_obj)

        return api_obj