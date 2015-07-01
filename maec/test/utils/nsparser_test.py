# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from maec.utils.nsparser import MAEC_NAMESPACES


class NSParserTests(unittest.TestCase):

    def test_import(self):
        """Verify that the namespace list was imported successfully."""
        self.assertTrue(MAEC_NAMESPACES)
        self.assertEqual(3, len(MAEC_NAMESPACES))


if __name__ == "__main__":
    unittest.main()
