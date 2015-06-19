# MAEC Behavior Reference Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
       
class BehaviorReference(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehaviorReferenceType    
    _namespace = _namespace

    behavior_idref = fields.TypedField("behavior_idref")

    def __init__(self, behavior_idref = None):
        super(BehaviorReference, self).__init__()
        self.behavior_idref = behavior_idref
