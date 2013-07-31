#MAEC Action Equivalence Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/15/2013

import maec
import maec.bindings.maec_package as package_binding
from cybox.core import ActionReference


class ActionEquivalence(maec.Entity):
    def init(self, id = None):
        super(ActionEquivalence, self).__init__()
        self.id = id
        self.action_references = []

    def to_obj(self):
        action_equivalence_obj = package_binding.ActionEquivalenceType()
        if self.id is not None : action_equivalence_obj.set_id(self.id)
        if len(self.action_references) > 0:
            for action_reference in self.action_references: action_equivalence_obj.add_Action_Reference(action_reference.to_obj())
        return action_equivalence_obj

    def to_dict(self):
        action_equivalence_dict = {}
        if self.id is not None : action_equivalence_dict['id'] = self.id
        if len(self.action_references) > 0:
            action_reference_list = []
            for action_reference in self.action_references: action_reference_list.append(action_reference.to_dict())
            action_equivalence_dict['action_references'] = action_reference_list
        return action_equivalence_dict

    @staticmethod
    def from_dict(action_equivalence_dict):
        if not action_equivalence_dict:
            return None
        action_equivalence_ = ActionEquivalence()
        action_equivalence_.id = action_equivalence_dict.get('id')
        action_equivalence_.action_references = [ActionReference.from_dict(x) for x in action_equivalence_dict.get('action_references', [])]
        return action_equivalence_

    @staticmethod
    def from_obj(action_equivalence_obj):
        if not action_equivalence_obj:
            return None
        action_equivalence_ = ActionEquivalence()
        action_equivalence_.id = action_equivalence_obj.get_id()
        action_equivalence_.action_references = [ActionReference.from_obj(x) for x in action_equivalence_obj.get_Action_Reference()]
        return action_equivalence_
        
class ActionEquivalenceList(maec.EntityList):
    _contained_type = ActionEquivalence
    _binding_class = package_binding.ActionEquivalenceListType
    _binding_var = "Action_Equivalence"
