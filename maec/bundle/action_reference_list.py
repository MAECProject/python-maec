#MAEC Action Reference List Class

#Copyright (c) 2014, The MITRE Corporation
#All rights reserved

#Compatible with MAEC v4.1
#Last updated 02/18/2014

from cybox.core import ActionReference

import maec
import maec.bindings.maec_bundle as bundle_binding


class ActionReferenceList(maec.EntityList):
    _contained_type = ActionReference
    _binding_class = bundle_binding.ActionReferenceListType
    _binding_var = "Action_Reference"
    _namespace = maec.bundle._namespace
