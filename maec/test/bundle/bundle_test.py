# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.bundle.bundle import Bundle
from maec.bundle.malware_action import MalwareAction
from cybox.core import Object
from maec.bundle.behavior import Behavior
from maec.bundle.candidate_indicator import CandidateIndicator

class TestBundle(EntityTestCase, unittest.TestCase):
    klass = Bundle

    _full_dict = {
        'defined_subject':False
    }

    def test_id_autoset(self):
        o = Bundle()
        self.assertNotEqual(o.id_, None)

    def test_round_trip(self):
        o = Bundle()
        o2 = round_trip(o, True)

        self.assertEqual(o.to_dict(), o2.to_dict())

    def test_add_collections(self):
        o = Bundle()

        o.add_named_action_collection("Actions")
        ma = MalwareAction()
        o.add_action(ma, "Actions")
        self.assertTrue(o.collections.action_collections.has_collection("Actions"))

        o.add_named_object_collection("Objects")
        obj = Object()
        o.add_object(obj, "Objects")
        self.assertTrue(o.collections.object_collections.has_collection("Objects"))

        o.add_named_behavior_collection("Behaviors")
        b = Behavior()
        o.add_behavior(b, "Behaviors")
        self.assertTrue(o.collections.behavior_collections.has_collection("Behaviors"))

        o.add_named_candidate_indicator_collection("Indicators")
        ci = CandidateIndicator()
        o.add_candidate_indicator(ci, "Indicators")
        self.assertTrue(o.collections.candidate_indicator_collections.has_collection("Indicators"))

if __name__ == "__main__":
    unittest.main()
