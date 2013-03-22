#MAEC Bundle Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 02/26/2013

import maec.bindings.maec_bundle_3_0 as bundle_binding
import cybox.bindings.commons as cybox_common
import datetime
       
class Behavior(object):
    def init(self, generator, id, description, ordinal_position):
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
        
        self.description = description
        self.ordinal_position = ordinal_position
    
    def set_known_vulnerability(self, cve_id, description):
        vuln = bundle_binding.VulnerabilityExploitType()
        cve = bundle_binding.CVEVulnerabilityType()
        cve.set_cve_id(cve_id)
        cve.set_Description(description)
        vuln.set_CVE(cve)
        vuln.set_known_vulnerability(True)
        self.purpose.set_Vulnerability_Exploit(vuln)
        
    def set_description(self, description):
        self.behavior.set_Description(description)
        
    def add_action(self, action):
        action_ref = bundle_binding.BehavioralActionReferenceType(action_id=action.get_idref(), behavioral_ordering=action.get_behavioral_ordering())
        self.actionComposition.add_Action_Reference(action_ref)

    def add_related_behavior(self, type, behavior):
        relationship = bundle_binding.BehaviorRelationshipType(type_=type)
        behavior_ref = bundle_binding.BehaviorReferenceType(behavior_idref = behavior.get_idref())
        relationship.add_Behavior_Reference(behavior_ref)
        self.relationships.add_Relationship(relationship)
        
    def set_oridinal_position(self, position):
        self.behavior.set_ordinal_position(position)
        
    def set_duration(self, duration):
        self.behavior.set_ordinal_duration(duration)
        
    #Accessor methods
    def get(self):
        self.__build__()
        return self.behavior
    
    def __build__(self):
        if self.discoveryMethod.hasContent_(): self.behavior.set_Discovery_Method(self.discoveryMethod)
        if self.actionComposition.hasContent_(): self.behavior.set_Action_Composition(self.actionComposition)
        if self.associatedCode.hasContent_(): self.behavior.set_Associated_Code(self.associatedCode)
        if self.relationships.hasContent_(): self.behavior.set_Relationships(self.relationships)
        if self.purpose.hasContent_(): self.behavior.set_Purpose(self.purpose)
        