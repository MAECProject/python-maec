#MAEC Bundle Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 02/26/2013

import maec.bindings.maec_bundle_3_0 as bundle_binding
import datetime
       
class ProcessTree(object):
    def init(self, root_process = None):
        self.processtree.set_Root_Process(root_process)
        
    def set_root_process(self, root_process):
        self.root_process = root_process
        
    #Accessor methods
    def to_obj(self):
        processtree = bundle_binding.ProcessTreeType()
        
        if self.root_process is not None:
            processtree.set_Root_Process(self.root_process)
            
        return processtree
    
    
class ProcessTreeNode(object):
    def init(self, id = None, parent_action_idref = None, spawned_process_list = None, injected_process_list = None, initiated_action_list = None):
        self.set_id(id)
        self.set_parent_action_ideref(parent_action_idref)
        
        if spawned_process_list is not None: self.spawned_list = spawned_process_list
        else: self.spawned_list = []
        
        if injected_process_list is not None: self.injected_list = injected_process_list
        else: self.injected_list = []
        
        if initiated_action_list is not None: self.initiated_list = initiated_action_list
        else: self.initiated_list = []
                

    def add_spawned_process(self, process_node):
        self.spawned_list.append(process_node)
        
    def add_injected_process(self, process_node):
        self.injected_list.append(process_node)
        
    def add_initiated_action(self, action):
        self.initiated_list.append(action)
        
    def set_id(self, id):
        self.id = id
        
    def set_parent_action_ideref(self, parent_action_idref):
        self.parent_action_idref = parent_action_idref
        
    def to_obj(self):
        node = bundle_binding.ProcessTreeNodeType(id = self.id)
        node.set_parent_action_idref(self.parent_action_idref)
        
        action_list = bundle_binding.ActionReferenceListType()
        for action in self.initiated_list:
            action_list.add_Action_Reference(action)
        node.set_Initiated_Actions(action_list)
        
        for process in self.spawned_list:
            node.add_Spawned_Process(process)
        for process in self.injected_list:
            node.add_Injected_Process(process)
            
        return node