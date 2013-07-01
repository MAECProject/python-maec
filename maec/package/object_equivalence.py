#MAEC Action Equivalence Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/15/2013

import maec
import maec.bindings.maec_package as package_binding
from maec.bundle.object_reference import ObjectReference    

class ObjectEquivalence(maec.Entity):
    def init(self, id = None):
        super(ObjectEquivalence, self).__init__()
        self.id = id
        self.object_references = []

    def to_obj(self):
        object_equivalence_obj = package_binding.ObjectEquivalenceType()
        if self.id is not None : object_equivalence_obj.set_id(self.id)
        if len(self.object_references) > 0:
            for object_reference in self.object_references: object_equivalence_obj.add_object_Reference(object_reference.to_obj())
        return object_equivalence_obj

    def to_dict(self):
        object_equivalence_dict = {}
        if self.id is not None : object_equivalence_dict['id'] = self.id
        if len(self.object_references) > 0:
            object_reference_list = []
            for object_reference in self.object_references: object_reference_list.append(object_reference.to_dict())
            object_equivalence_dict['object_references'] = object_reference_list
        return object_equivalence_dict

    @staticmethod
    def from_dict(object_equivalence_dict):
        if not object_equivalence_dict:
            return None
        object_equivalence_ = ObjectEquivalence()
        object_equivalence_.id = object_equivalence_dict.get('id')
        object_equivalence_.object_references = [ObjectReference.from_dict(x) for x in object_equivalence_dict.get('object_references', [])]
        return object_equivalence_

    @staticmethod
    def from_obj(object_equivalence_obj):
        if not object_equivalence_obj:
            return None
        object_equivalence_ = ObjectEquivalence()
        object_equivalence_.id = object_equivalence_obj.get_id()
        object_equivalence_.object_references = [ObjectReference.from_obj(x) for x in object_equivalence_obj.get_object_Reference()]
        return object_equivalence_

class ObjectEquivalenceList(maec.EntityList):
    _contained_type = ObjectEquivalence
    _binding_class = package_binding.ObjectEquivalenceListType
    _binding_var = "Object_Equivalence"