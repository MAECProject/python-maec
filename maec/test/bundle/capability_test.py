# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.bundle.capability import Capability

class TestCapability(EntityTestCase, unittest.TestCase):
    klass = Capability

    _full_dict = {
        'description':'Perform some action',
        'strategic_objective':[{
            'name': {
                'vocab_reference':'http://maec.mitre.org/XMLSchema/default_vocabularies/2.1/maec_default_vocabularies.xsd#DataTheftStrategicObjectivesVocab-1.0',
                'value':'steal stored information'
            },
            'property':[{
                'name': {
                    'vocab_reference': 'http://maec.mitre.org/XMLSchema/default_vocabularies/2.1/maec_default_vocabularies.xsd#CommonCapabilityPropertiesVocab-1.0',
                    'value':'encryption algorithm'
                },
                'value': 'AES-256'
            },
            {
                'name': {
                    'vocab_reference': 'http://maec.mitre.org/XMLSchema/default_vocabularies/2.1/maec_default_vocabularies.xsd#CommonCapabilityPropertiesVocab-1.0',
                    'value':'protocol used'
                },
                'value': 'TCP'
            }]
        }],
        'tactical_objective':[{
            'name': {
                'vocab_reference':'http://maec.mitre.org/XMLSchema/default_vocabularies/2.1/maec_default_vocabularies.xsd#FraudTacticalObjectivesVocab-1.0',
                'value':'access premium service'
            }
        }]
    }

    def test_id_autoset(self):
        o = Capability()
        self.assertNotEqual(o.id_, None)

    def test_round_trip(self):
        o = Capability()
        o2 = round_trip(o, True)

        self.assertEqual(o.to_dict(), o2.to_dict())

if __name__ == "__main__":
    unittest.main()