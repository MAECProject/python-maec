# MAEC Candidate Indicator Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle import ObjectReference, BehaviorReference
from cybox.common import VocabString
from cybox.core import ActionReference

class MalwareEntity(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.MalwareEntityType    
    _namespace = _namespace

    type_ = fields.TypedField("Type", VocabString)
    name = fields.TypedField("Name")
    description = fields.TypedField("Description")

    def __init__(self):
        super(MalwareEntity, self).__init__()

class CandidateIndicatorComposition(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.CandidateIndicatorCompositionType    
    _namespace = _namespace

    operator = fields.TypedField("operator")
    behavior_reference = fields.TypedField("Behavior_Reference", BehaviorReference, multiple = True)
    action_reference = fields.TypedField("Action_Reference", ActionReference, multiple = True)
    object_reference = fields.TypedField("Object_Reference", ObjectReference, multiple = True)
    sub_composition = fields.TypedField("Sub_Composition", multiple = True)

    def __init__(self):
        super(CandidateIndicatorComposition, self).__init__()

# Allow recursive definition of CandidateIndicatorCompositions
CandidateIndicatorComposition.sub_composition.type_ = CandidateIndicatorComposition

class CandidateIndicator(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.CandidateIndicatorType    
    _namespace = _namespace

    id_ = fields.TypedField("id")
    creation_datetime = fields.TypedField("creation_datetime")
    lastupdate_datetime = fields.TypedField("lastupdate_datetime")
    version = fields.TypedField("version")
    importance = fields.TypedField("Importance", VocabString)
    numeric_importance = fields.TypedField("Numeric_Importance")
    author = fields.TypedField("Author")
    description = fields.TypedField("Description")
    malware_entity = fields.TypedField("Malware_Entity", MalwareEntity)
    composition = fields.TypedField("Composition", CandidateIndicatorComposition)

    def __init__(self, id = None):
        super(CandidateIndicator, self).__init__()
        if id:
            id_ = id
        else:
            id_ = maec.utils.idgen.create_id(prefix="candidate_indicator")

class CandidateIndicatorList(maec.EntityList):
    _contained_type = CandidateIndicator
    _binding_class = bundle_binding.CandidateIndicatorListType
    _binding_var = "Candidate_Indicator"
    _namespace = _namespace
