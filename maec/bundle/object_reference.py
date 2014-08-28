# MAEC Object Reference Class

# Copyright (c) 2014, The MITRE Corporation
# All rights reserved

# Compatible with MAEC v4.1
# Last updated 08/28/2014

import maec
import maec.bindings.maec_bundle as bundle_binding       

class ObjectReference(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.ObjectReferenceType
    _namespace = maec.bundle._namespace

    def __init__(self, object_idref = None):
        super(ObjectReference, self).__init__()
        self.object_idref = object_idref
        
class ObjectReferenceList(maec.EntityList):
    _contained_type = ObjectReference
    _binding_class = bundle_binding.ObjectReferenceListType
    _binding_var = "Object_Reference"
    _namespace = maec.bundle._namespace