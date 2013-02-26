#MAEC Bundle Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 02/26/2013

import maec.bindings.maec_bundle_3_0 as bundle_binding
import datetime
       
class ProcessTree(object):
    def init(self, root_process = None):
        self.processtree = bundle_binding.ProcessTreeType()
        if root_process is not None:
            self.processtree.set_Root_Process(root_process)
        
    def set_root_process(self, root_process):
        self.processtree.set_Root_Process(root_process)
        
    #Accessor methods
    def get(self):
        return self.processtree
    
    
class ProcessTreeNode(object):
    def init(self):
        self.node = bundle_binding.ProcessTreeNodeType()
        self.action_list = bundle_binding.ActionReferenceListType()
        
    def add_spawned_process(self, process_node):
        self.node.add_Spawned_Process(process_node)
        
    def add_injected_process(self, process_node):
        self.node.add_Injected_Process(process_node)
        
    def add_initiated_action(self, action):
        self.action_list.add_Action_Reference(action)
        
    def set_id(self, id):
        self.node.set_id(id)
        
    def set_parent_action_ideref(self, parent_action_idref):
        self.node.set_parent_action_idref(parent_action_idref)
        
    #Accessor methods
    def get(self):
        self.__build__()
        return self.processtree
    
    def __build__(self):
        if self.action_list.hasContent_(): self.node.set_Initiated_Actions(self.action_list)
