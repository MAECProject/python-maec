#MAEC Action Equivalence Class

#Copyright (c) 2014, The MITRE Corporation
#All rights reserved

#Compatible with MAEC v4.1
#Last updated 08/20/2014

import cybox
import maec
import maec.bindings.maec_package as package_binding
from maec.bundle.object_reference import ObjectReference    

class ObjectEquivalence(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ObjectEquivalenceType
    _namespace = maec.package._namespace

    id_ = maec.TypedField("id")
    object_reference = maec.TypedField("Object_Reference", ObjectReference, multiple = True)

    def init(self, id = None):
        super(ObjectEquivalence, self).__init__()
        self.id_ = id

class ObjectEquivalenceList(maec.EntityList):
    _contained_type = ObjectEquivalence
    _binding_class = package_binding.ObjectEquivalenceListType
    _binding_var = "Object_Equivalence"
    _namespace = maec.package._namespace