# MAEC Behavior Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
from cybox.core.action_reference import ActionReference
from cybox.common.measuresource import MeasureSource
from cybox.common.platform_specification import PlatformSpecification
from cybox.objects.code_object import Code
#from maec.bundle.bundle import ActionCollection

class BehavioralActionEquivalenceReference(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehavioralActionEquivalenceReferenceType    
    _namespace = _namespace

    action_equivalence_idref = maec.TypedField('action_equivalence_idref')
    behavioral_ordering = maec.TypedField('behavioral_ordering')

class BehavioralActionReference(ActionReference):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehavioralActionReferenceType    
    _namespace = _namespace

    behavioral_ordering = maec.TypedField('behavioral_ordering')

class BehavioralAction(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehavioralActionType    
    _namespace = _namespace

    behavioral_ordering = maec.TypedField('behavioral_ordering')

class BehavioralActions(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehavioralActionsType    
    _namespace = _namespace

    #action_collection = maec.TypedField('Action_Collection', ActionCollection, multiple=True) #TODO: solve recursive import
    action = maec.TypedField('Action', BehavioralAction, multiple=True)
    action_reference = maec.TypedField('Action_Reference', BehavioralActionReference, multiple=True)
    action_equivalence_reference = maec.TypedField('Action_Equivalence_Reference', BehavioralActionEquivalenceReference, multiple=True)

class PlatformList(maec.EntityList):
    _binding = bundle_binding
    _binding_class = bundle_binding.PlatformListType
    _binding_var = "Platform"
    _contained_type = PlatformSpecification    
    _namespace = _namespace

class CVEVulnerability(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.CVEVulnerabilityType    
    _namespace = _namespace

    cve_id = maec.TypedField('cve_id')
    description = maec.TypedField('Description')

class Exploit(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.ExploitType    
    _namespace = _namespace
    
    known_vulnerability = maec.TypedField('known_vulnerability')
    cve = maec.TypedField('CVE', CVEVulnerability)
    cwe_id = maec.TypedField('CWE_ID', multiple=True)
    targeted_platforms = maec.TypedField('Targeted_Platforms', PlatformList)

class BehaviorPurpose(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehaviorPurposeType       
    _namespace = _namespace

    description = maec.TypedField('Description')
    vulnerability_exploit = maec.TypedField('Vulnerability_Exploit', Exploit)

class AssociatedCode(maec.EntityList):
    _binding = bundle_binding
    _binding_class = bundle_binding.AssociatedCodeType
    _binding_var = "Code_Snippet"
    _contained_type = Code    
    _namespace = _namespace

class Behavior(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehaviorType  
    _namespace = _namespace

    id_ = maec.TypedField('id')
    ordinal_position = maec.TypedField('ordinal_position')
    status = maec.TypedField('status')
    duration = maec.TypedField('duration')
    purpose = maec.TypedField('Purpose', BehaviorPurpose)
    description = maec.TypedField('Description')
    discovery_method = maec.TypedField('Discovery_Method', MeasureSource)
    action_composition = maec.TypedField('Action_Composition', BehavioralActions)
    associated_code = maec.TypedField('Associated_Code', AssociatedCode)
    #relationships = maec.TypedField('Relationships', BehaviorRelationshipList) # TODO: implement

    def __init__(self, id = None, description = None):
        super(Behavior, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="behavior")
        self.description = description
