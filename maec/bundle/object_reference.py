#MAEC Object Reference Class

#Copyright (c) 2014, The MITRE Corporation
#All rights reserved

#Compatible with MAEC v4.1
#Last updated 02/18/2014

import maec
import maec.bindings.maec_bundle as bundle_binding       

class ObjectReference(maec.Entity):
    _namespace = maec.bundle._namespace

    def init(self, object_idref = None):
        super(ObjectReference, self).__init__()
        self.object_idref = object_idref

    def to_obj(self):
        object_reference_obj = bundle_binding.ObjectReferenceType()
        if self.object_idref is not None : object_reference_obj.set_object_idref(self.object_idref)
        return object_reference_obj

    def to_dict(self):
        object_reference_dict = {}
        if self.object_idref is not None : object_reference_dict['object_idref'] = self.object_idref
        return object_reference_dict

    @staticmethod
    def from_dict(object_reference_dict):
        if not object_reference_dict:
            return None
        object_reference_ = ObjectReference()
        object_reference_.object_idref = object_reference_dict.get('object_idref')
        return object_reference_

    @staticmethod
    def from_obj(object_reference_obj):
        if not object_reference_obj:
            return None
        object_reference_ = ObjectReference()
        object_reference_.object_idref = object_reference_obj.get_object_idref()
        return object_reference_
        
class ObjectReferenceList(maec.EntityList):
    _contained_type = ObjectReference
    _binding_class = bundle_binding.ObjectReferenceListType
    _binding_var = "Object_Reference"
    _namespace = maec.bundle._namespace