#MAEC Capability Class

#Copyright (c) 2014, The MITRE Corporation
#All rights reserved


#Compatible with MAEC v4.1
#Last updated 02/18/2014

import maec
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle.behavior_reference import BehaviorReference
from cybox.common import VocabString, String

class CapabilityObjectiveReference(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self):
        super(CapabilityObjectiveReference, self).__init__()
        self.objective_idref = None

    def to_obj(self):
        capability_objective_reference_obj = bundle_binding.CapabilityObjectiveReferenceType()
        if self.objective_idref is not None: capability_objective_reference_obj.set_objective_idref(self.objective_idref)
        return capability_objective_reference_obj

    def to_dict(self):
        capability_objective_reference_dict = {}
        if self.objective_idref is not None: capability_objective_reference_dict['capability_idref'] = self.objective_idref
        return capability_objective_reference_dict

    @staticmethod
    def from_obj(capability_objective_reference_obj):
        if not capability_objective_reference_obj:
            return None
        capability_objective_reference_ = CapabilityObjectiveReference()
        capability_objective_reference_.objective_idref = capability_objective_reference_obj.get_objective_idref()
        return capability_objective_reference_

    @staticmethod
    def from_dict(capability_objective_reference_dict):
        if not capability_objective_reference_dict:
            return None
        capability_objective_reference_ = CapabilityObjectiveReference()
        capability_objective_reference_.objective_idref = capability_objective_reference_dict['objective_idref']
        return capability_objective_reference_

class CapabilityReference(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self):
        super(CapabilityReference, self).__init__()
        self.capability_idref = None

    def to_obj(self):
        capability_reference_obj = bundle_binding.CapabilityReferenceType()
        if self.capability_idref is not None: capability_reference_obj.set_capability_idref(self.capability_idref)
        return capability_reference_obj

    def to_dict(self):
        capability_reference_dict = {}
        if self.capability_idref is not None: capability_reference_dict['capability_idref'] = self.capability_idref
        return capability_reference_dict

    @staticmethod
    def from_obj(capability_reference_obj):
        if not capability_reference_obj:
            return None
        capability_reference_ = CapabilityReference()
        capability_reference_.capability_idref = capability_reference_obj.get_capability_idref()
        return capability_reference_

    @staticmethod
    def from_dict(capability_reference_dict):
        if not capability_reference_dict:
            return None
        capability_reference_ = CapabilityReference()
        capability_reference_.capability_idref = capability_reference_dict['capability_idref']
        return capability_reference_

class CapabilityObjectiveRelationship(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self):
        super(CapabilityObjectiveRelationship, self).__init__()
        self.relationship_type = None
        self.objective_reference = []

    def to_obj(self):
        capability_obj_rel_obj = bundle_binding.CapabilityObjectiveRelationshipType()
        if self.relationship_type is not None: capability_obj_rel_obj.set_Relationship_Type(self.relationship_type.to_obj())
        if self.objective_reference is not None:
            for objective_ref in self.objective_reference: 
                capability_obj_rel_obj.add_Objective_Reference(objective_ref.to_obj())
        return capability_obj_rel_obj

    def to_dict(self):
        capability_obj_rel_dict = {}
        if self.relationship_type is not None: capability_obj_rel_dict['relationship_type'] = self.relationship_type.to_dict()
        if self.objective_reference is not None:
            capability_obj_rel_dict['objective_reference'] = [x.to_dict() for x in self.objective_reference]
        return capability_obj_rel_dict

    @staticmethod
    def from_obj(capability_obj_rel_obj):
        if not capability_obj_rel_obj:
            return None
        capability_obj_rel_ = CapabilityObjectiveRelationship()
        capability_obj_rel_.relationship_type = VocabString.from_obj(capability_obj_rel_obj.get_Relationship_Type())
        if capability_obj_rel_obj.get_Objective_Reference():
            capability_obj_rel_.objective_reference = [CapabilityObjectiveReference.from_obj(x) for x in capability_obj_rel_obj.get_Objective_Reference()]
        return capability_obj_rel_

    @staticmethod
    def from_dict(capability_obj_rel_dict):
        if not capability_obj_rel_dict:
            return None
        capability_obj_rel_ = CapabilityRelationship()
        capability_obj_rel_.relationship_type = VocabString.from_dict(capability_obj_rel_dict['relationship_type'])
        if capability_obj_rel_dict['objective_reference']:
            capability_obj_rel_.objective_reference = [CapabilityObjectiveReference.from_dict(x) for x in capability_obj_rel_dict['objective_reference']]
        return capability_obj_rel_

class CapabilityRelationship(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self):
        super(CapabilityRelationship, self).__init__()
        self.relationship_type = None
        self.capability_reference = []

    def to_obj(self):
        capability_rel_obj = bundle_binding.CapabilityRelationshipType()
        if self.relationship_type is not None: capability_rel_obj.set_Relationship_Type(self.relationship_type.to_obj())
        if self.capability_reference is not None:
            for capability_ref in self.capability_reference: 
                capability_rel_obj.add_Capability_Reference(capability_ref.to_obj())
        return capability_rel_obj

    def to_dict(self):
        capability_rel_dict = {}
        if self.relationship_type is not None: capability_rel_dict['relationship_type'] = self.relationship_type.to_dict()
        if self.capability_reference is not None:
            capability_rel_dict['capability_reference'] = [x.to_dict() for x in self.capability_reference]
        return capability_rel_dict

    @staticmethod
    def from_obj(capability_rel_obj):
        if not capability_rel_obj:
            return None
        capability_rel_ = CapabilityRelationship()
        capability_rel_.relationship_type = VocabString.from_obj(capability_rel_obj.get_Relationship_Type())
        if capability_rel_obj.get_Capability_Reference():
            capability_rel_.capability_reference = [CapabilityReference.from_obj(x) for x in capability_rel_obj.get_Capability_Reference()]
        return capability_rel_

    @staticmethod
    def from_dict(capability_rel_dict):
        if not capability_rel_dict:
            return None
        capability_rel_ = CapabilityRelationship()
        capability_rel_.relationship_type = VocabString.from_dict(capability_rel_dict['relationship_type'])
        if capability_rel_dict['capability_reference']:
            capability_rel_.capability_reference = [CapabilityReference.from_dict(x) for x in capability_rel_dict['capability_reference']]
        return capability_rel_

class CapabilityObjective(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self):
        super(CapabilityObjective, self).__init__()
        self.id_ = maec.utils.idgen.create_id(prefix="capability_objective")
        self.name = None
        self.description = None
        self.property = []
        self.behavior_reference = []
        self.relationship = []

    def to_obj(self):
        capability_objective_obj = bundle_binding.CapabilityObjectiveType()
        if self.id_ is not None: capability_objective_obj.set_id(self.id_)
        if self.name is not None: capability_objective_obj.set_Name(self.name.to_obj())
        if self.description is not None: capability_objective_obj.set_Description(self.description.to_obj())
        if self.property: 
            for prop in self.property:
                capability_objective_obj.add_Property(prop.to_obj())
        if self.behavior_reference: 
            for behavior_ref in self.behavior_reference:
                capability_objective_obj.add_Behavior_Reference(behavior_ref.to_obj())
        if self.relationship: 
            for rel in self.relationship:
                capability_objective_obj.add_Relationship(rel.to_obj())
        return capability_objective_obj

    def to_dict(self):
        capability_objective_dict = {}
        if self.id_ is not None: capability_objective_dict['id'] = self.id_
        if self.name is not None: capability_objective_dict['name'] = self.name.to_dict()
        if self.description is not None: capability_objective_dict['description'] = self.description
        if self.property: 
            capability_objective_dict['property'] = [x.to_dict() for x in self.property]
        if self.behavior_reference: 
            capability_objective_dict['behavior_reference'] = [x.to_dict() for x in self.behavior_reference]
        if self.relationship: 
            capability_objective_dict['relationship'] = [x.to_dict() for x in self.relationship]

        return capability_objective_dict

    @staticmethod
    def from_obj(capability_objective_obj):
        if not capability_objective_obj:
            return None
        capability_objective_ = CapabilityObjective()
        if capability_objective_obj.get_id(): capability_objective_.id_ = capability_objective_obj.get_id()
        capability_objective_.name = VocabString.from_obj(capability_objective_obj.get_Name())
        capability_objective_.description = capability_objective_obj.get_Description()
        if capability_objective_obj.get_Property(): 
            capability_objective_.property = [CapabilityProperty.from_obj(x) for x in capability_objective_obj.get_Property()]
        if capability_objective_obj.get_Behavior_Reference(): 
            capability_objective_.behavior_reference = [BehaviorReference.from_obj(x) for x in capability_objective_obj.get_Behavior_Reference()]
        if capability_objective_obj.get_Relationship(): 
            capability_objective_.relationship = [CapabilityObjectiveRelationship.from_obj(x) for x in capability_objective_obj.get_Relationship()]
        return capability_objective_

    @staticmethod
    def from_dict(capability_objective_dict):
        if not capability_objective_dict:
            return None
        capability_objective_ = CapabilityObjective()
        if capability_objective_dict.get('id'): capability_objective_.id_ = capability_objective_dict.get('id')
        capability_objective_.name = VocabString.from_dict(capability_objective_dict.get('name'))
        capability_objective_.description = capability_objective_dict.get('description')
        if capability_objective_dict.get('property'): 
            capability_objective_.property = [CapabilityProperty.from_dict(x) for x in capability_objective_dict.get('property')]
        if capability_objective_dict.get('behavior_reference'): 
            capability_objective_.behavior_reference = [BehaviorReference.from_dict(x) for x in capability_objective_dict.get('behavior_reference')]
        if capability_objective_dict.get('relationship'): 
            capability_objective_.relationship = [CapabilityObjectiveRelationship.from_dict(x) for x in capability_objective_dict.get('relationship')]
        return capability_objective_
       
class CapabilityProperty(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self):
        super(CapabilityProperty, self).__init__()
        self.name = None
        self.value = None

    def to_obj(self):
        capability_property_obj = bundle_binding.CapabilityPropertyType()
        if self.name is not None: capability_property_obj.set_Name(self.name.to_obj())
        if self.value is not None: capability_property_obj.set_Value(self.value.to_obj())
        return capability_property_obj

    def to_dict(self):
        capability_property_dict = {}
        if self.name is not None: capability_property_dict['name'] = self.name.to_dict()
        if self.value is not None: capability_property_dict['value'] = self.value.to_dict()
        return capability_property_dict

    @staticmethod
    def from_obj(capability_property_obj):
        if not capability_property_obj:
            return None
        capability_property_ = CapabilityProperty()
        capability_property_.name = VocabString.from_obj(capability_property_obj.get_Name())
        capability_property_.value = String.from_obj(capability_property_obj.get_Value())
        return capability_property_

    @staticmethod
    def from_dict(capability_property_dict):
        if not capability_property_obj:
            return None
        capability_property_ = CapabilityProperty()
        capability_property_.name = VocabString.from_dict(capability_property_dict['name'])
        capability_property_.value = String.from_dict(capability_property_dict['value'])
        return capability_property_

class Capability(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self, id = None, name = None):
        super(Capability, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="capability")
        self.name = name
        self.description = None
        self.property = []
        self.strategic_objective = []
        self.tactical_objective = []
        self.behavior_reference = []
        self.relationship = []

    def add_tactical_objective(self, tactical_objective):
        self.tactical_objective.append(tactical_objective)

    def add_strategic_objective(self, strategic_objective):
        self.strategic_objective.append(strategic_objective)

    def to_obj(self):
        capability_obj = bundle_binding.CapabilityType()
        if self.id_ is not None: capability_obj.set_id(self.id_)
        if self.name is not None: capability_obj.set_name(self.name)
        if self.description is not None: capability_obj.set_Description(self.description)
        if self.property: 
            for prop in self.property:
                capability_obj.add_Property(prop.to_obj())
        if self.strategic_objective: 
            for strategic_obj in self.strategic_objective:
                capability_obj.add_Strategic_Objective(strategic_obj.to_obj())
        if self.tactical_objective: 
            for tactical_obj in self.tactical_objective:
                capability_obj.add_Tactical_Objective(tactical_obj.to_obj())
        if self.behavior_reference: 
            for behavior_ref in self.behavior_reference:
                capability_obj.add_Behavior_Reference(behavior_ref.to_obj())
        if self.relationship: 
            for rel in self.relationship:
                capability_obj.add_Relationship(rel.to_obj())

        return capability_obj

    def to_dict(self):
        capability_dict = {}
        if self.id_ is not None: capability_dict['id'] = self.id_
        if self.name is not None: capability_dict['name'] = self.name
        if self.description is not None: capability_dict['description'] = self.description
        if self.property: 
            capability_dict['property'] = [x.to_dict() for x in self.property]
        if self.strategic_objective: 
            capability_dict['strategic_objective'] = [x.to_dict() for x in self.strategic_objective]
        if self.tactical_objective: 
            capability_dict['tactical_objective'] = [x.to_dict() for x in self.tactical_objective]
        if self.behavior_reference: 
            capability_dict['behavior_reference'] = [x.to_dict() for x in self.behavior_reference]
        if self.relationship: 
            capability_dict['relationship'] = [x.to_dict() for x in self.relationship]

        return capability_dict
        
    @staticmethod
    def from_dict(capability_dict):
        if not capability_dict:
            return None
        capability_ = Capability()
        if capability_dict.get('id'): capability_.id_ = capability_dict.get('id')
        capability_.name = capability_dict.get('name')
        capability_.description = capability_dict.get('description')
        if capability_dict.get('property'): 
            capability_.property = [CapabilityProperty.from_dict(x) for x in capability_dict.get('property')]
        if capability_dict.get('strategic_objective'): 
            capability_.strategic_objective = [CapabilityObjective.from_dict(x) for x in capability_dict.get('strategic_objective')]
        if capability_dict.get('tactical_objective'): 
            capability_.tactical_objective = [CapabilityObjective.from_dict(x) for x in capability_dict.get('tactical_objective')]
        if capability_dict.get('behavior_reference'): 
            capability_.behavior_reference = [BehaviorReference.from_dict(x) for x in capability_dict.get('behavior_reference')]
        if capability_dict.get('relationship'): 
            capability_.relationship = [CapabilityRelationship.from_dict(x) for x in capability_dict.get('relationship')]
        return capability_

    @staticmethod
    def from_obj(capability_obj):
        if not capability_obj:
            return None
        capability_ = Capability()
        if capability_obj.get_id(): capability_.id_ = capability_obj.get_id()
        capability_.name = capability_obj.get_name()
        capability_.description = capability_obj.get_Description()
        if capability_obj.get_Property(): 
            capability_.property = [CapabilityProperty.from_obj(x) for x in capability_obj.get_Property()]
        if capability_obj.get_Strategic_Objective(): 
            capability_.strategic_objective = [CapabilityObjective.from_obj(x) for x in capability_obj.get_Strategic_Objective()]
        if capability_obj.get_Tactical_Objective(): 
            capability_.tactical_objective = [CapabilityObjective.from_obj(x) for x in capability_obj.get_Tactical_Objective()]
        if capability_obj.get_Behavior_Reference(): 
            capability_.behavior_reference = [BehaviorReference.from_obj(x) for x in capability_obj.get_Behavior_Reference()]
        if capability_obj.get_Relationship(): 
            capability_.relationship = [CapabilityRelationship.from_obj(x) for x in capability_obj.get_Relationship()]
        return capability_
        
class CapabilityList(maec.Entity):
    _namespace = maec.bundle._namespace

    def __init__(self):
        super(CapabilityList, self).__init__()
        self.capability = []
        self.capability_reference = []

    def to_obj(self):
        capability_list_obj = bundle_binding.CapabilityListType()
        if self.capability:
            for cap in self.capability:
                capability_list_obj.add_Capability(cap.to_obj())
        if self.capability_reference:
            for cap_ref in self.capability_reference:
                capability_list_obj.add_Capability_Reference(cap_ref.to_obj())
        return capability_list_obj

    def to_dict(self):
        capability_list_dict = {}
        if self.capability:
            capability_list_dict['capability'] = [x.to_dict() for x in self.capability]
        if self.capability_reference:
            capability_list_dict['capability_reference'] = [x.to_dict() for x in self.capability_reference]
        return capability_list_dict

    @staticmethod
    def from_obj(capability_list_obj):
        if not capability_list_obj:
            return None
        capability_list_ = CapabilityList()
        if capability_list_obj.get_Capability():
            capability_list_.capability = [Capability.from_obj(x) for x in capability_list_obj.get_Capability()]
        if capability_list_obj.get_Capability_Reference(): 
            capability_list_.capability_reference = [CapabilityReference.from_obj(x) for x in capability_list_obj.get_Capability_Reference()]
        return capability_list_

    @staticmethod
    def from_dict(capability_list_dict):
        if not capability_list_dict:
            return None
        capability_list_ = CapabilityList()
        if capability_list_dict['capability']:
            capability_list_.capability = [Capability.from_dict(x) for x in capability_list_dict['capability']]
        if capability_list_dict['capability_reference']:
            capability_list_.capability_reference = [CapabilityReference.from_dict(x) for x in capability_list_dict['capability_reference']]
        return capability_list_