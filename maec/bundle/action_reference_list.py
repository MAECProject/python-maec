#MAEC Action Reference List Class

#Copyright (c) 2018, The MITRE Corporation
#All rights reserved

from cybox.core import ActionReference

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
from mixbox import fields

class ActionReferenceList(maec.EntityList):
    _binding_class = bundle_binding.ActionReferenceListType
    _namespace = _namespace
    action_reference = fields.TypedField("Action_Reference", ActionReference, multiple=True)
