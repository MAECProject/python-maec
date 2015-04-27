# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.package import Package

class TestPackage(EntityTestCase, unittest.TestCase):
    klass = Package

    _full_dict = {
        'malware_subjects':[{
            'findings_bundles': {
                'bundle': [{
                    'actions': [{
                        'associated_objects': [{
                            'association_type': {
                                'value': u'output',
                                'xsi:type': 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'
                            },
                            'id': 'example:Object-fdba414a-e46a-4abf-ad50-4dcda819129c',
                            'properties': {
                                'file_name': u'abcd.dll',
                                'size_in_bytes': 123456L,
                                'xsi:type': 'FileObjectType'
                            }
                        }],
                        'id': 'example:action-912c7a09-91f5-4737-9b5a-129eb42488bf',
                        'name': {
                            'value': u'create file',
                            'xsi:type': 'maecVocabs:FileActionNameVocab-1.0'
                        },
                    }],
                    'capabilities': {
                        'capability': [{
                            'id': 'example:capability-5b1f99c6-203b-422d-831e-b440a1a32052',
                            'name': 'persistence'

                        }],
                    },
                    'defined_subject': False,
                    'id': 'example:bundle-09642c48-9136-4f46-98b2-e8f9fb6f69ad',
                    'schema_version': '4.1'
                }]
            },
            'id': 'example:malware_subject-89f6a399-badf-43cc-bf66-fd97c66ce4b2',
            'malware_instance_object_attributes': {
                'id': 'example:Object-aeb67018-a0e9-4199-bafa-1f0c581fb315',
                'properties': {
                    'hashes': [{
                        'simple_hash_value': u'8743b52063cd84097a65d1633f5c74f5',
                        'type': u'MD5'
                    }],
                    'size_in_bytes': 35532L,
                    'xsi:type': 'FileObjectType'
                }
            }}],
        'grouping_relationships':[{'type':{'value':'same malware family',
                                           'xsi:type':'maecVocabs:GroupingRelationshipTypeVocab-1.0'}}]
    }

    def test_id_autoset(self):
        o = Package()
        self.assertNotEqual(o.id_, None)

    def test_round_trip(self):
        o = Package()
        o2 = round_trip(o)

        self.assertEqual(o.to_dict(), o2.to_dict())

if __name__ == "__main__":
    unittest.main()
    
