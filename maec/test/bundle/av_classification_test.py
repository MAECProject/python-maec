# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.bundle.av_classification import AVClassification

class TestAVClassification(EntityTestCase, unittest.TestCase):
    klass = AVClassification

    _full_dict = {
        'classification_name':'Some!Trojan',
        'vendor':'McAfee'
    }

    def test_round_trip(self):
        o = AVClassification('Some!Trojan')
        o.vendor = 'McAfee'
        o2 = round_trip(o, True)

        self.assertEqual(o.to_dict(), o2.to_dict())

if __name__ == "__main__":
    unittest.main()
