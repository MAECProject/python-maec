#MAEC Behavior Reference Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/10/2013

import maec
import maec.bindings.maec_bundle as bundle_binding
       
class BehaviorReference(maec.Entity):
    def init(self, behavior_idref = None):
        super(BehaviorReference, self).__init__()
        self.behavior_idref = behavior_idref

    def to_obj(self):
        behavior_reference_obj = bundle_binding.BehaviorReferenceType()
        if self.behavior_idref is not None : behavior_reference_obj.set_behavior_idref(self.behavior_idref)
        return behavior_reference_obj

    def to_dict(self):
        behavior_reference_dict = {}
        if self.behavior_idref is not None : behavior_reference_dict['behavior_idref'] = self.behavior_idref
        return behavior_reference_dict

    @staticmethod
    def from_dict(behavior_reference_dict):
        if not behavior_reference_dict:
            return None
        behavior_reference_ = BehaviorReference()
        behavior_reference_.behavior_idref = behavior_reference_dict.get('behavior_idref')
        return behavior_reference_

    @staticmethod
    def from_obj(behavior_reference_obj):
        if not behavior_reference_obj:
            return None
        behavior_reference_ = BehaviorReference()
        behavior_reference_.behavior_idref = behavior_reference_obj.get_behavior_idref()
        return behavior_reference_
        