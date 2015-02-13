# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.bundle.bundle import Behavior

class TestBehavior(EntityTestCase, unittest.TestCase):
    klass = Behavior

    _full_dict = {
        'ordinal_position': 1,
        'status': 'Success',
        'duration': 'PT3S',
        'description': 'Malware engages in some behavior wherein...',
        'purpose': {
            'description': 'Here is why the malware does this...',
            'vulnerability_exploit': {
                'known_vulnerability': True,
                'cve': {
                    'cve_id': 'CVE-2013-1337',
                    'description': '.NET vulnerability'
                },
                'targeted_platforms': [{ 'description': 'Windows ME' }]
            }
        },
        'action_composition': {
            'action':[{ 'behavioral_ordering': 1 }],
            'action_reference':[{ 'action_id': 'some_id' }],
            'action_equivalence_reference':[{ 'behavioral_ordering': 1 }]
        }
    }

    def test_id_autoset(self):
        o = Behavior()
        self.assertNotEqual(o.id_, None)

    def test_round_trip(self):
        o = Behavior()
        o2 = round_trip(o, True)

        self.assertEqual(o.to_dict(), o2.to_dict())

if __name__ == "__main__":
    unittest.main()