# MAEC Object Reference Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding       

class ObjectReference(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.ObjectReferenceType
    _namespace = _namespace

    def __init__(self, object_idref = None):
        super(ObjectReference, self).__init__()
        self.object_idref = object_idref
        
class ObjectReferenceList(maec.EntityList):
    _binding_class = bundle_binding.ObjectReferenceListType
    _namespace = _namespace
    object_reference = fields.TypedField("Object_Reference", ObjectReference, multiple=True)
