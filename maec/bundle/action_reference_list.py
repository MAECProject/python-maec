#MAEC Action Reference List Class

#Copyright (c) 2015, The MITRE Corporation
#All rights reserved

from cybox.core import ActionReference

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding


class ActionReferenceList(maec.EntityList):
    _contained_type = ActionReference
    _binding_class = bundle_binding.ActionReferenceListType
    _binding_var = "Action_Reference"
    _namespace = _namespace
