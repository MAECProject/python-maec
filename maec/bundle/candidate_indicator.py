# MAEC Candidate Indicator Class

# Copyright (c) 2014, The MITRE Corporation
# All rights reserved

# Compatible with MAEC v4.1
# Last updated 08/27/2014

import maec
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle.object_reference import ObjectReference
from maec.bundle.behavior_reference import BehaviorReference
from cybox.common import VocabString
from cybox.core import ActionReference

class MalwareEntity(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.MalwareEntityType    
    _namespace = maec.bundle._namespace

    type_ = maec.TypedField("Type", VocabString)
    name = maec.TypedField("Name")
    description = maec.TypedField("Description")

    def __init__(self):
        super(MalwareEntity, self).__init__()

class CandidateIndicatorComposition(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.CandidateIndicatorCompositionType    
    _namespace = maec.bundle._namespace

    operator = maec.TypedField("operator")
    behavior_reference = maec.TypedField("Behavior_Reference", BehaviorReference, multiple = True)
    action_reference = maec.TypedField("Action_Reference", ActionReference, multiple = True)
    object_reference = maec.TypedField("Object_Reference", ObjectReference, multiple = True)
    sub_composition = maec.TypedField("Sub_Composition", multiple = True)

    def __init__(self):
        super(CandidateIndicatorComposition, self).__init__()

# Allow recursive definition of CandidateIndicatorCompositions
CandidateIndicatorComposition.sub_composition.type_ = CandidateIndicatorComposition

class CandidateIndicator(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.CandidateIndicatorType    
    _namespace = maec.bundle._namespace

    id_ = maec.TypedField("id")
    creation_datetime = maec.TypedField("creation_datetime")
    lastupdate_datetime = maec.TypedField("lastupdate_datetime")
    version = maec.TypedField("version")
    importance = maec.TypedField("Importance", VocabString)
    numeric_importance = maec.TypedField("Numeric_Importance")
    author = maec.TypedField("Author")
    description = maec.TypedField("Description")
    malware_entity = maec.TypedField("Malware_Entity", MalwareEntity)
    composition = maec.TypedField("Composition", CandidateIndicatorComposition)

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
    _namespace = maec.bundle._namespace