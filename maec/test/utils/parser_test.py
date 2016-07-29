# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from mixbox.vendor.six import StringIO
import unittest

from mixbox.parser import (UnknownVersionError, UnsupportedRootElementError,
                           UnsupportedVersionError)

from maec.bundle import Bundle
from maec.package import Package
from maec.utils import EntityParser


class ParserTests(unittest.TestCase):

    def test_valid_package(self):
        valid_package = """
        <maecPackage:MAEC_Package
            xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-2"
            id="example:package-1" schema_version="2.1">
        </maecPackage:MAEC_Package>
        """

        parser = EntityParser()
        package = parser.parse_xml(StringIO(valid_package))

        self.assertEqual(Package, type(package))
        self.assertEqual("example:package-1", package.id_)

    def test_valid_bundle(self):
        valid_bundle = """
        <maecBundle:MAEC_Bundle
            xmlns:maecBundle="http://maec.mitre.org/XMLSchema/maec-bundle-4"
            id="example:bundle-1" schema_version="4.1">
        </maecBundle:MAEC_Bundle>
        """

        parser = EntityParser()
        package = parser.parse_xml(StringIO(valid_bundle))

        self.assertEqual("example:bundle-1", package.id_)

    def test_wrong_root_element(self):
        wrong_root = """
        <maecPackage:NotAPackage
            xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-2"
            id="example:package-1" schema_version="2.1">
        </maecPackage:NotAPackage>
        """

        parser = EntityParser()
        self.assertRaises(UnsupportedRootElementError,
                          parser.parse_xml, StringIO(wrong_root))

        # If there's not a valid root element, there's no way to check the
        # version number.
        self.assertRaises(UnsupportedVersionError,
                          parser.parse_xml, StringIO(wrong_root),
                          check_root=False)

    def test_wrong_version(self):
        wrong_version = """
        <maecPackage:MAEC_Package
            xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-2"
            id="example:package-1" schema_version="10.1.8">
        </maecPackage:MAEC_Package>
        """

        parser = EntityParser()
        self.assertRaises(UnsupportedVersionError,
                          parser.parse_xml, StringIO(wrong_version))

        package = parser.parse_xml(StringIO(wrong_version),
                                   check_version=False)

        self.assertEqual("example:package-1", package.id_)
        self.assertEqual("10.1.8", package.schema_version)

    def test_missing_version(self):
        missing_version = """
        <maecPackage:MAEC_Package
            xmlns:maecPackage="http://maec.mitre.org/XMLSchema/maec-package-2"
            id="example:package-1">
        </maecPackage:MAEC_Package>
        """

        parser = EntityParser()
        self.assertRaises(UnknownVersionError,
                          parser.parse_xml, StringIO(missing_version))

        package = parser.parse_xml(StringIO(missing_version),
                                   check_version=False)

        self.assertEqual("example:package-1", package.id_)


if __name__ == "__main__":
    unittest.main()
