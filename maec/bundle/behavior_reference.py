# MAEC Behavior Reference Class

# Copyright (c) 2014, The MITRE Corporation
# All rights reserved

# Compatible with MAEC v4.1
# Last updated 08/28/2014

import maec
import maec.bindings.maec_bundle as bundle_binding
       
class BehaviorReference(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehaviorReferenceType    
    _namespace = maec.bundle._namespace

    behavior_idref = maec.TypedField("behavior_idref")

    def __init__(self, behavior_idref = None):
        super(BehaviorReference, self).__init__()
        self.behavior_idref = behavior_idref