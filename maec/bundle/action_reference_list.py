#MAEC Action Reference List Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/15/2013

import maec
import maec.bindings.maec_bundle as bundle_binding
from cybox.core.action_reference import ActionReference

class ActionReferenceList(maec.EntityList):
    _contained_type = ActionReference
    _binding_class = bundle_binding.ActionReferenceListType

    def __init__(self):
        super(ActionReferenceList, self).__init__()

    @staticmethod
    def _set_list(binding_obj, list_):
        binding_obj.set_Action_Reference(list_)

    @staticmethod
    def _get_list(binding_obj):
        return binding_obj.get_Action_Reference()