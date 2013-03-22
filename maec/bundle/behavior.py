#MAEC Bundle Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 02/26/2013

import maec.bindings.maec_bundle_3_0 as bundle_binding
import cybox.bindings.commons as cybox_common
import datetime
       
class Behavior(object):
    def init(self, generator, id, description, ordinal_position, duration, status):
        if id is not None:
            self.id = id
        elif generator is not None:
            self.generator = generator;
            self.id = self.generator.generate_bundle_id()
        else:
            raise Exception("Must specify id or generator for Behavior constructor")
        
        self.behavior = bundle_binding.BehaviorType(self.id)
        self.discoveryMethod = cybox_common.MeasureSourceType()
        self.actionComposition = bundle_binding.BehavioralActionsType()
        self.associatedCode = bundle_binding.AssociatedCodeType()
        self.relationships = bundle_binding.BehaviorRelationshipListType()
        
        self.purpose = bundle_binding.BehaviorPurposeType()
        self.exploit = bundle_binding.VulnerabilityExploitType()
        self.platformList = bundle_binding.PlatformListType()
        
        if ordinal_position is not None: self.behavior.set_ordinal_position(ordinal_position)
        if description is not None: self.behavior.set_Description(description)
        if duration is not None: self.behavior.set_duration(duration)
        if status is not None: self.behavior.set_status(status)
    
    def add_targeted_platform(self, platform):
        self.platformList.add_Platform(platform)
        self.exploit.set_known_vulnerability(False)
    
    def set_known_vulnerability(self, cve_id, description):
        cve = bundle_binding.CVEVulnerabilityType()
        cve.set_cve_id(cve_id)
        cve.set_Description(description)
        self.exploit.set_CVE(cve)
        self.exploit.set_known_vulnerability(True)
        
    def set_discovery_method(self, cybox_measuresource_obj):
        self.behavior.set_Discovery_Method(cybox_measuresource_obj)
        
    def add_action(self, action):
        action_ref = bundle_binding.BehavioralActionReferenceType(action_id=action.get_id(), behavioral_ordering=action.get_behavioral_ordering())
        self.actionComposition.add_Action_Reference(action_ref)

    def add_code_snippet(self, cybox_code_obj):
        self.associatedCode.add_Code_Snippet(cybox_code_obj)

    def add_related_behavior(self, type, behavior):
        relationship = bundle_binding.BehaviorRelationshipType(type_=type)
        behavior_ref = bundle_binding.BehaviorReferenceType(behavior_idref = behavior.get_id())
        relationship.add_Behavior_Reference(behavior_ref)
        self.relationships.add_Relationship(relationship)
        
            
    def set_description(self, description):
        self.behavior.set_Description(description)
        
    def set_oridinal_position(self, position):
        self.behavior.set_ordinal_position(position)
        
    def set_duration(self, duration):
        self.behavior.set_duration(duration)
        
    def set_status(self, status):
        self.behavior.set_status(status)
        
    #Accessor methods
    def get(self):
        self.__build__()
        return self.behavior
    
    def __build__(self):
        if self.discoveryMethod.hasContent_(): self.behavior.set_Discovery_Method(self.discoveryMethod)
        if self.actionComposition.hasContent_(): self.behavior.set_Action_Composition(self.actionComposition)
        if self.associatedCode.hasContent_(): self.behavior.set_Associated_Code(self.associatedCode)
        if self.relationships.hasContent_(): self.behavior.set_Relationships(self.relationships)
        
        # purpose elements
        if self.platformList.hasContent_(): self.exploit.set_Targeted_Platforms(self.platformList)
        if self.exploit.hasContent_(): self.purpose.set_Vulnerability_Exploit(self.exploit)
        if self.purpose.hasContent_(): self.behavior.set_Purpose(self.purpose)
        
        