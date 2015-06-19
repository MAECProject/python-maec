# MAEC Process Tree classes

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

from cybox.objects.process_object import Process

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle import ActionReferenceList


class ProcessTreeNode(Process):
    _binding = bundle_binding
    _binding_class = bundle_binding.ProcessTreeNodeType
    _namespace = _namespace
    _XSI_NS = "maecBundle"
    _XSI_TYPE = "ProcessTreeNodeType"
    superclass = Process

    id_ = fields.TypedField("id")
    parent_action_idref = fields.TypedField("parent_action_idref")
    ordinal_position = fields.TypedField("ordinal_position")
    initiated_actions = fields.TypedField("Initiated_Actions", ActionReferenceList)
    spawned_process = fields.TypedField("Spawned_Process", multiple = True)
    injected_process = fields.TypedField("Injected_Process", multiple = True)

    def __init__(self, id = None, parent_action_idref = None):
        super(ProcessTreeNode, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="process_tree")
        self.parent_action_idref = parent_action_idref

    def add_spawned_process(self, process_node, process_id = None):
        """Add a spawned process to the Process Tree node, either directly or to a
           particular process embedded in the node based on its ID."""
        if not process_id:
            if not self.spawned_process:
                self.spawned_process = []
            self.spawned_process.append(process_node)
        elif process_id:
            if str(self.pid) == process_id:
                if not self.spawned_process:
                    self.spawned_process = []
                self.spawned_process.append(process_node)
            else:
                embedded_process = self.find_embedded_process(process_id)
                if embedded_process:
                    if not embedded_process.spawned_process:
                        embedded_process.spawned_process = []
                    embedded_process.spawned_process.append(process_node)

    def add_injected_process(self, process_node, process_id = None):
        """Add an injected process to the Process Tree node, either directly or to a
           particular process embedded in the node based on its ID."""
        if not process_id:
            if not self.injected_process:
                self.injected_process = []
            self.injected_process.append(process_node)
        elif process_id:
            if str(self.pid) == process_id:
                if not self.injected_process:
                    self.injected_process = []
                self.injected_process.append(process_node)
            else:
                embedded_process = self.find_embedded_process(process_id)
                if embedded_process:
                    if not embedded_process.injected_process:
                        embedded_process.injected_process = []
                    embedded_process.injected_process.append(process_node)

    def add_initiated_action(self, action_id):
        """Add an initiated Action to the Process Tree node, based on its ID."""
        if not self.initiated_actions:
            self.initiated_actions = ActionReferenceList()
        self.initiated_actions.append(action_id)

    def find_embedded_process(self, process_id):
        """Find a Process embedded somewhere in the Process Tree node tree, based on its ID."""
        embedded_process = None
        if self.spawned_process:
            for spawned_process in self.spawned_process:
                if str(spawned_process.pid) == str(process_id):
                    embedded_process = spawned_process
                else:
                    embedded_process = spawned_process.find_embedded_process(process_id)
        if self.injected_process:
            for injected_process in self.injected_process:
                if str(injected_process.pid) == str(process_id):
                    embedded_process = injected_process
                else:
                    embedded_process = injected_process.find_embedded_process(process_id)
        return embedded_process

    def set_id(self, id):
        """Set the ID of the Process Tree node."""
        self.id_ = id

    def set_parent_action(self, parent_action_id):
        """Set the ID of the parent action of the Process Tree node."""
        self.parent_action_idref = parent_action_id


class ProcessTree(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.ProcessTreeType    
    _namespace = _namespace

    root_process = fields.TypedField("Root_Process", ProcessTreeNode)

    def __init__(self, root_process = None):
        super(ProcessTree, self).__init__()
        self.root_process = root_process

    def set_root_process(self, root_process):
        """Set the Root Process node of the Process Tree entity."""
        self.root_process = root_process

# Allow recursive definition of ProcessTreeNodes
ProcessTreeNode.spawned_process.type_ = ProcessTreeNode
ProcessTreeNode.injected_process.type_ = ProcessTreeNode
