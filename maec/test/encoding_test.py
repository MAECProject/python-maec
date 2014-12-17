# -*- coding: utf-8 -*-
# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""Tests for various encoding issues throughout the library"""

import unittest
from StringIO import StringIO

import maec.bindings as bindings
from maec.package.malware_subject import MalwareConfigurationParameter
from maec.package.analysis import DynamicAnalysisMetadata
from maec.package.grouping_relationship import GroupingRelationship
from maec.bundle.bundle import Bundle
from maec.bundle.av_classification import AVClassification
from maec.bundle.behavior import Behavior
from maec.bundle.capability import Capability

from cybox.test import round_trip

UNICODE_STR = u"❤ ♎ ☀ ★ ☂ ♞ ☯ ☭ ☢ €☎⚑ ❄♫✂"

class EncodingTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.orig_encoding = bindings.ExternalEncoding
        bindings.ExternalEncoding = 'utf-16'

    @classmethod
    def tearDownClass(cls):
        bindings.ExternalEncoding = cls.orig_encoding

    def test_malware_configuration_parameter(self):
        config = MalwareConfigurationParameter()
        config.value = UNICODE_STR
        config2 = round_trip(config)
        self.assertEqual(config.value, config2.value)

    def test_dynamic_analysis_metadata(self):
        metadata = DynamicAnalysisMetadata()
        metadata.command_line = UNICODE_STR
        metadata2 = round_trip(metadata)
        self.assertEqual(metadata.command_line, metadata2.command_line)

    def test_grouping_relationship(self):
        relationship = GroupingRelationship()
        relationship.malware_family_name = UNICODE_STR
        relationship.malware_toolkit_name = UNICODE_STR
        relationship2 = round_trip(relationship)
        self.assertEqual(relationship.malware_family_name, relationship2.malware_family_name)
        self.assertEqual(relationship.malware_toolkit_name, relationship2.malware_toolkit_name)

    def test_behavior(self):
        behavior = Behavior()
        behavior.description = UNICODE_STR
        behavior2 = round_trip(behavior)
        self.assertEqual(behavior.description, behavior2.description)

    def test_capability(self):
        capability = Capability()
        capability.description = UNICODE_STR
        capability2 = round_trip(capability)
        self.assertEqual(capability.description, capability2.description)

    def test_av_classification(self):
        av_class = AVClassification()
        av_class.engine_version = UNICODE_STR
        av_class.definition_version = UNICODE_STR
        av_class.classification_name = UNICODE_STR
        av_class2 = round_trip(av_class)
        self.assertEqual(av_class.engine_version, av_class2.engine_version)
        self.assertEqual(av_class.definition_version, av_class2.definition_version)
        self.assertEqual(av_class.classification_name, av_class2.classification_name)

    def test_quote_xml(self):
        s = bindings.quote_xml(UNICODE_STR)
        self.assertEqual(s, UNICODE_STR)

    def test_quote_attrib(self):
        """Tests that the maec.bindings.quote_attrib method works properly
        on unicode inputs.

        Note:
            The quote_attrib method (more specifically, saxutils.quoteattr())
            adds quotation marks around the input data, so we need to strip
            the leading and trailing chars to test effectively
        """
        s = bindings.quote_attrib(UNICODE_STR)
        s = s[1:-1]
        self.assertEqual(s, UNICODE_STR)

    def test_quote_attrib_int(self):
        i = 65536
        s = bindings.quote_attrib(i)
        self.assertEqual(u'"65536"', s)

    def test_quote_attrib_bool(self):
        b = True
        s = bindings.quote_attrib(b)
        self.assertEqual(u'"True"', s)

    def test_quote_xml_int(self):
        i = 65536
        s = bindings.quote_xml(i)
        self.assertEqual(unicode(i), s)

    def test_quote_xml_bool(self):
        b = True
        s = bindings.quote_xml(b)
        self.assertEqual(unicode(b), s)

    def test_quote_xml_encoded(self):
        encoding = bindings.ExternalEncoding
        encoded = UNICODE_STR.encode(encoding)
        quoted = bindings.quote_xml(encoded)
        self.assertEqual(UNICODE_STR, quoted)

    def test_quote_attrib_encoded(self):
        encoding = bindings.ExternalEncoding
        encoded = UNICODE_STR.encode(encoding)
        quoted = bindings.quote_attrib(encoded)[1:-1]
        self.assertEqual(UNICODE_STR, quoted)

    def test_quote_xml_zero(self):
        i = 0
        s = bindings.quote_xml(i)
        self.assertEqual(unicode(i), s)

    def test_quote_attrib_zero(self):
        i = 0
        s = bindings.quote_attrib(i)
        self.assertEqual(u'"0"', s)

    def test_quote_xml_none(self):
        i = None
        s = bindings.quote_xml(i)
        self.assertEqual(u'', s)

    def test_quote_attrib_none(self):
        i = None
        s = bindings.quote_attrib(i)
        self.assertEqual(u'""', s)

    def test_quote_attrib_empty(self):
        i = ''
        s = bindings.quote_attrib(i)
        self.assertEqual(u'""', s)

    def test_quote_xml_empty(self):
        i = ''
        s = bindings.quote_xml(i)
        self.assertEqual(u'', s)

    def test_to_xml_utf16_encoded(self):
        encoding = 'utf-16'
        b = Behavior()
        b.description = UNICODE_STR
        xml = b.to_xml(encoding=encoding)
        self.assertTrue(UNICODE_STR in xml.decode(encoding))

    def test_to_xml_default_encoded(self):
        b = Behavior()
        b.description = UNICODE_STR
        xml = b.to_xml()
        self.assertTrue(UNICODE_STR in xml.decode('utf-8'))

    def test_to_xml_no_encoding(self):
        b = Behavior()
        b.description = UNICODE_STR
        xml = b.to_xml(encoding=None)
        self.assertTrue(isinstance(xml, unicode))
        self.assertTrue(UNICODE_STR in xml)

if __name__ == "__main__":
    unittest.main()