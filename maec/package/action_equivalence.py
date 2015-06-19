#MAEC Action Equivalence Class

#Copyright (c) 2015, The MITRE Corporation
#All rights reserved

from mixbox import fields

import maec
from . import _namespace
import maec.bindings.maec_package as package_binding
from cybox.core import ActionReference

class ActionEquivalence(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ActionEquivalenceType
    _namespace = _namespace

    id_ = fields.TypedField('id')
    action_reference = fields.TypedField('Action_Reference', ActionReference, multiple = True)

    def __init__(self):
        super(ActionEquivalence, self).__init__()
        self.id_ = maec.utils.idgen.create_id(prefix="action_equivalence")

class ActionEquivalenceList(maec.EntityList):
    _contained_type = ActionEquivalence
    _binding_class = package_binding.ActionEquivalenceListType
    _binding_var = "Action_Equivalence"
    _namespace = _namespace
