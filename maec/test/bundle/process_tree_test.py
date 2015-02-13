# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest

from cybox.test import EntityTestCase, round_trip
from maec.bundle.process_tree import ProcessTree, ProcessTreeNode

class TestCapability(EntityTestCase, unittest.TestCase):
    klass = ProcessTree

    _full_dict = {
        "root_process": {
            "xsi:type": "ProcessTreeNodeType",
            "id": "example:process_tree-7f44d6ed-1a0b-4bff-ae57-1491b751444f",
            "injected_process": [{
                 "xsi:type": "ProcessTreeNodeType",
                 "id": "example:process_tree-2897a24c-5f0b-4850-a995-578c98f47ed7"
            }],
            "spawned_process": [{
                "xsi:type": "ProcessTreeNodeType",
                "id": "example:process_tree-3aacff1f-2c78-46c7-8e71-95d1a61dc05a",
                "spawned_process": [{
                    "xsi:type": "ProcessTreeNodeType",
                    "id": "example:process_tree-a355d96b-8545-4ce5-b7e5-86670076ecf8"
                 }]
            }, {
                "xsi:type": "ProcessTreeNodeType",
                "id": "example:process_tree-d5589470-c6a5-4d54-a576-62e79c9ba8a0"
            }]
        }
    }


    def test_id_autoset(self):
        o = ProcessTreeNode()
        self.assertNotEqual(o.id_, None)

    def test_round_trip(self):
        o = ProcessTree()
        root = ProcessTreeNode()
        spawned_child1 = ProcessTreeNode()
        spawned_child2 = ProcessTreeNode()
        injected_child = ProcessTreeNode()
        spawned_grandchild = ProcessTreeNode()
        
        o.set_root_process(root)
        root.add_spawned_process(spawned_child1)
        root.add_spawned_process(spawned_child2)
        root.add_injected_process(injected_child)
        spawned_child1.add_spawned_process(spawned_grandchild)
        
        o2 = round_trip(o, True)

        self.assertEqual(o.to_dict(), o2.to_dict())

if __name__ == "__main__":
    unittest.main()