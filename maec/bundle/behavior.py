#MAEC Bundle Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/10/2013

import maec
import maec.bindings.maec_bundle as bundle_binding
import datetime
       
class Behavior(maec.Entity):
    def __init__(self, id, description = None, ordinal_position = None, duration = None, status = None):
        self.id = id
        self.action_list = []
        self.platform_list = []
        self.snippet_list = []
        self.relationship_list = []
        
        self.discovery_method = None
        self.cve_id = None
        self.cve_description = None
        self.purpose_description = None
        
        self.set_ordinal_position(ordinal_position)
        self.set_description(description)
        self.set_duration(duration)
        self.set_status(status)
        
    def add_related_behavior(self, type, behavior):
        self.relationship_list.append({
                                       type: type,
                                       behavior: behavior
                                       })
    
    def add_code_snippet(self, cybox_code_obj):
        self.snippet_list.append(cybox_code_obj)
        
    def add_targeted_platform(self, platform):
        self.platform_list.append(platform)
        self.known_vulnerability = False
    
    def set_known_vulnerability(self, cve_id, cve_description):
        self.cve_id = cve_id
        self.cve_description = cve_description
    
    def set_discovery_method(self, cybox_measuresource_obj):
        self.discoveryMethod = cybox_measuresource_obj
        
    def add_action(self, action):
        self.action_list.append(action)
    
    def set_description(self, description):
        self.description = description
        
    def set_ordinal_position(self, position):
        self.position = position
        
    def set_duration(self, duration):
        self.duration = duration
        
    def set_status(self, status):
        self.status = status
        
    def set_purpose_description(self, purpose_description):
        self.purpose_description = purpose_description
        
    def to_obj(self):
        behavior = bundle_binding.BehaviorType(self.id)
        if self.duration is not None: behavior.set_duration(self.duration)
        if self.status is not None: behavior.set_status(self.status)
        if self.position is not None: behavior.set_ordinal_position(self.position)
        if self.description is not None: behavior.set_Description(self.description)
        
        if self.discovery_method is not None and self.discovery_method.hasContent_():
            behavior.set_Discovery_Method(self.discovery_method)
        
        exploit = bundle_binding.VulnerabilityExploitType()
        exploit.set_known_vulnerability(False)
        cve = bundle_binding.CVEVulnerabilityType()
        if self.cve_id is not None: cve.set_cve_id(self.cve_id)
        if self.cve_description is not None: cve.set_Description(self.cve_description)
        if cve.hasContent_():
            exploit.set_CVE(cve)
            exploit.set_known_vulnerability(True)
        
        platformList = bundle_binding.PlatformListType()
        for platform in self.platform_list:
            platformList.add_Platform(platform)
        if platformList.hasContent_(): exploit.set_Targeted_Platforms(platformList)
        
        purpose = bundle_binding.BehaviorPurposeType()
        if self.purpose_description is not None: purpose.set_Description(self.purpose_description)
        if exploit.hasContent_(): purpose.set_Vulnerability_Exploit(exploit)
        if purpose.hasContent_(): behavior.set_Purpose(purpose)
        
        relationships = bundle_binding.BehaviorRelationshipListType()
        for relation_dict in self.relationship_list:
            relationship = bundle_binding.BehaviorRelationshipType(type_=relation_dict.type)
            behavior_ref = bundle_binding.BehaviorReferenceType(behavior_idref = relation_dict.behavior.get_id())
            relationship.add_Behavior_Reference(behavior_ref)
            relationships.add_Relationship(relationship)
        if relationships.hasContent_(): behavior.set_Relationships(relationships)
        
        associatedCode = bundle_binding.AssociatedCodeType()
        for cybox_code_obj in self.snippet_list:
            associatedCode.add_Code_Snippet(cybox_code_obj)
        if associatedCode.hasContent_(): behavior.set_Associated_Code(associatedCode)
        
        actionComposition = bundle_binding.BehavioralActionsType()
        for action in self.action_list:
            action_ref = bundle_binding.BehavioralActionReferenceType(action_id=action.get_id(), behavioral_ordering=action.get_behavioral_ordering())
            actionComposition.add_Action_Reference(action_ref)
        if actionComposition.hasContent_(): behavior.set_Action_Composition(actionComposition)
        
        return behavior
        