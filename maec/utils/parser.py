# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import mixbox.parser
from mixbox.parser import (UnknownVersionError, UnsupportedVersionError,
                           UnsupportedRootElementError)

# Alias for backwards compatibility
UnsupportedRootElement = UnsupportedRootElementError

TAG_MAEC_BUNDLE = "{http://maec.mitre.org/XMLSchema/maec-bundle-4}MAEC_Bundle"
TAG_MAEC_PACKAGE = "{http://maec.mitre.org/XMLSchema/maec-package-2}MAEC_Package"


class EntityParser(mixbox.parser.EntityParser):

    def supported_tags(self):
        return [TAG_MAEC_BUNDLE, TAG_MAEC_PACKAGE]

    def get_version(self, root):
        return root.attrib.get('schema_version')

    def supported_versions(self, tag):
        if tag == TAG_MAEC_BUNDLE:
            return ['4.1']
        elif tag == TAG_MAEC_PACKAGE:
            return ['2.1']
        else:
            return []

    def get_entity_class(self, tag):
        if tag == TAG_MAEC_BUNDLE:
            from maec.bundle import Bundle
            return Bundle
        elif tag == TAG_MAEC_PACKAGE:
            from maec.package import Package
            return Package
