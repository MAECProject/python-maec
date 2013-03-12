#MAEC Bundle Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 02/26/2013

import maec.bindings.maec_bundle_3_0 as bundle_binding
import cybox.bindings.commons as cybox_common
import datetime
       
class Behavior(object):
    def init(self, generator):
        self.generator = generator;
        
        self.behavior = bundle_binding.BehaviorType(id=self.generator.generate_bundle_id())
        self.discoveryMethod = cybox_common.MeasureSourceType()
        self.actionComposition = bundle_binding.BehavioralActionsType()
        self.associatedCode = bundle_binding.AssociatedCodeType()
        self.relationships = bundle_binding.BehaviorRelationshipListType()
        
    def set_purpose(self, purpose):
        pass
    
    def set_description(self, description):
        self.behavior.set_Description(description)
        
    def set_action_composition(self, action_composition):
        pass
        
    def add_related_behavior(self, related_behavior_ref):
        relationship = bundle_binding.BehaviorRelationshipType()
        relationship.add_Behavior_Reference(related_behavior_ref)
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
    