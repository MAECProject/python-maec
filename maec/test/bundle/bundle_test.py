# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.bundle.bundle import Bundle

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

if __name__ == "__main__":
    unittest.main()
