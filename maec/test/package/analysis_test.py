# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.package.analysis import Analysis, Source


class TestPackage(EntityTestCase, unittest.TestCase):
    klass = Analysis

    _full_dict = {
        "source": {
            "url": "http://www.threatexpert.com",
            "organization": "ThreatExpert",
            "name": "ThreatExpert",
            "method": "triage"
        },
        "start_datetime": "2014-08-06T18:30:00",
        "id": "example:analysis-5e1a1095-65a7-459e-9272-2c7883d9c20f"
    }


    def test_id_autoset(self):
        o = Analysis()
        self.assertNotEqual(o.id_, None)

    def test_round_trip(self):
        o = Analysis()
        o.source = Source()
        o.source.name = "ThreatExpert"
        o.source.organization = "ThreatExpert"
        o.source.method = "triage"
        o.source.url = "http://www.threatexpert.com"
        
        o.start_datetime = "2014-08-06T18:30:00"
        
        o2 = round_trip(o, True)

        self.assertEqual(o.to_dict(), o2.to_dict())

if __name__ == "__main__":
    unittest.main()