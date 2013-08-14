#MAEC Candidate Indicator Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 08/14/2013

import maec
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle.object_reference import ObjectReference
from maec.bundle.behavior_reference import BehaviorReference
from cybox.common import VocabString
from cybox.core import ActionReference

class CandidateIndicator(maec.Entity):
    def init(self, id, generator):
        super(CandidateIndicator, self).__init__()
        if id is not None:
            self.id = id
        elif generator is not None:
            self.generator = generator
            self.id = self.generator.generate_candidate_indicator_id()
        else:
            raise Exception("Must specify id or generator for CandidateIndicator constructor")
        self.creation_datetime = None
        self.lastupdate_datetime = None
        self.version = None
        self.importance = None
        self.numeric_importance = None
        self.author = None
        self.description = None
        self.malware_entity = None
        self.composition = None
        
    def to_obj(self):
        candidate_indicator_obj = bundle_binding.CandidateIndicatorType()
        if self.id is not None : candidate_indicator_obj.set_id(self.id)
        if self.creation_datetime is not None : candidate_indicator_obj.set_creation_datetime(self.creation_datetime)
        if self.version is not None : candidate_indicator_obj.set_version(self.version)
        if self.importance is not None : candidate_indicator_obj.set_Importance(self.importance.to_obj())
        if self.numeric_importance is not None : candidate_indicator_obj.set_Numeric_Importance(self.numeric_importance)
        if self.author is not None : candidate_indicator_obj.set_Numeric_Importance(self.author)
        if self.description is not None : candidate_indicator_obj.set_Description(self.description)
        if self.malware_entity is not None : candidate_indicator_obj.set_Malware_Entity(self.malware_entity.to_obj())
        if self.composition is not None : candidate_indicator_obj.set_Composition(self.composition.to_obj())
        return candidate_indicator_obj

    def to_dict(self):
        candidate_indicator_dict = {}
        if self.id is not None : candidate_indicator_dict['id'] = self.id
        if self.creation_datetime is not None : candidate_indicator_dict['creation_datetime'] = self.creation_datetime
        if self.version is not None : candidate_indicator_dict['version'] = self.version
        if self.importance is not None : candidate_indicator_dict['importance'] = self.importance.to_dict()
        if self.numeric_importance is not None : candidate_indicator_dict['numeric_importance'] = self.numeric_importance
        if self.author is not None : candidate_indicator_dict['author'] = self.author
        if self.description is not None : candidate_indicator_dict['description'] = self.description
        if self.malware_entity is not None : candidate_indicator_dict['malware_entity'] = self.malware_entity.to_dict()
        if self.composition is not None : candidate_indicator_dict['composition'] = self.composition.to_dict()
        return candidate_indicator_dict

    @staticmethod
    def from_dict(candidate_indicator_dict):
        if not candidate_indicator_dict:
            return None
        candidate_indicator_ = CandidateIndicator()
        candidate_indicator_.id = candidate_indicator_dict.get('id')
        candidate_indicator_.creation_datetime = candidate_indicator_dict.get('creation_datetime')
        candidate_indicator_.version = candidate_indicator_dict.get('version')
        candidate_indicator_.importance = VocabString.from_dict(candidate_indicator_dict.get('importance'))
        candidate_indicator_.numeric_importance = candidate_indicator_dict.get('numeric_importance')
        candidate_indicator_.author = candidate_indicator_dict.get('author')
        candidate_indicator_.description = candidate_indicator_dict.get('description')
        candidate_indicator_.malware_entity = MalwareEntity.from_dict(candidate_indicator_dict.get('malware_entity'))
        candidate_indicator_.composition = CandidateIndicatorComposition.from_dict(candidate_indicator_dict.get('composition'))
        return candidate_indicator_

    @staticmethod
    def from_obj(candidate_indicator_obj):
        if not candidate_indicator_dict:
            return None
        candidate_indicator_ = CandidateIndicator()
        candidate_indicator_.id = candidate_indicator_obj.get_id()
        candidate_indicator_.creation_datetime = candidate_indicator_obj.get_creation_datetime()
        candidate_indicator_.version = candidate_indicator_obj.get_version()
        candidate_indicator_.importance = VocabString.from_obj(candidate_indicator_obj.get_Importance())
        candidate_indicator_.numeric_importance = candidate_indicator_obj.get_Numeric_Importance()
        candidate_indicator_.author = candidate_indicator_obj.get_Author()
        candidate_indicator_.description = candidate_indicator_obj.get_Description()
        candidate_indicator_.malware_entity = MalwareEntity.from_obj(candidate_indicator_obj.get_Malware_Entity())
        candidate_indicator_.composition = CandidateIndicatorComposition.from_obj(candidate_indicator_obj.get_Composition())
        return candidate_indicator_

class MalwareEntity(maec.Entity):
    def __init__(self):
        super(MalwareEntity, self).__init__()
        self.type = None
        self.name = None
        self.description = None

    def to_obj(self):
        malware_entity_obj = bundle_binding.MalwareEntityType()
        if self.type is not None : malware_entity_obj.set_Type(self.type.to_obj())
        if self.name is not None : malware_entity_obj.set_Name(self.name)
        if self.description is not None : malware_entity_obj.set_Description(self.description)
        return malware_entity_obj

    def to_dict(self):
        malware_entity_dict = {}
        if self.type is not None : malware_entity_dict['type'] = self.type.to_dict()
        if self.name is not None : malware_entity_dict['name'] = self.name
        if self.description is not None : malware_entity_dict['description'] = self.description
        return malware_entity_dict

    @staticmethod
    def from_dict(malware_entity_dict):
        if not malware_entity_dict:
            return None
        malware_entity_ = MalwareEntity()
        malware_entity_.type = VocabString.from_dict(malware_entity_dict.get('type'))
        malware_entity_.name = malware_entity_dict.get('name')
        malware_entity_.description = malware_entity_dict.get('description')
        return malware_entity_

    @staticmethod
    def from_obj(malware_entity_obj):
        if not malware_entity_obj:
            return None
        malware_entity_ = MalwareEntity()
        malware_entity_.type =  VocabString.from_obj(malware_entity_obj.get_Type())
        malware_entity_.name = malware_entity_obj.get_Name()
        malware_entity_.description = malware_entity_obj.get_Description()
        return malware_entity_

class CandidateIndicatorComposition(maec.Entity):
    def __init__(self):
        super(CandidateIndicatorComposition, self).__init__()
        self.operator = None
        self.behavior_references = []
        self.action_references = []
        self.object_references = []
        self.sub_compositions = []

    def to_obj(self):
        candidate_indc_comp_obj = bundle_binding.CandidateIndicatorCompositionType()
        if self.operator is not None : candidate_indc_comp_obj.set_operator(self.operator)
        if len(self.behavior_references) > 0: 
            for behavior_reference in self.behavior_references: candidate_indc_comp_obj.add_Behavior_Reference(behavior_reference.to_obj())
        if len(self.action_references) > 0: 
            for action_reference in self.action_references: candidate_indc_comp_obj.add_Action_Reference(action_reference.to_obj())
        if len(self.object_references) > 0: 
            for object_reference in self.object_references: candidate_indc_comp_obj.add_Object_Reference(object_reference.to_obj())
        if len(self.sub_compositions) > 0: 
            for sub_composition in self.object_references: candidate_indc_comp_obj.add_Sub_Composition(sub_composition.to_obj())
        return candidate_indc_comp_obj

    def to_dict(self):
        candidate_indc_comp_dict = {}
        if self.operator is not None : candidate_indc_comp_dict['operator'] = self.operator
        if len(self.behavior_references) > 0: 
            behavior_reference_list = []
            for behavior_reference in self.behavior_references: behavior_reference_list.append(behavior_reference.to_dict())
            candidate_indc_comp_dict['behavior_references'] = behavior_reference_list
        if len(self.action_references) > 0: 
            action_reference_list = []
            for action_reference in self.action_references: action_reference_list.append(action_reference.to_dict())
            candidate_indc_comp_dict['action_references'] = action_reference_list
        if len(self.object_references) > 0: 
            object_reference_list = []
            for object_reference in self.object_references: object_reference_list.append(object_reference.to_dict())
            candidate_indc_comp_dict['object_references'] = object_reference_list
        if len(self.sub_compositions) > 0: 
            sub_composition_list = []
            for sub_composition in self.sub_compositions: sub_composition_list.append(sub_composition.to_dict())
            candidate_indc_comp_dict['sub_compositions'] = sub_composition_list
        return candidate_indc_comp_dict

    @staticmethod
    def from_dict(candidate_indc_comp_dict):
        if not candidate_indc_comp_dict:
            return None
        candidate_indicator_composition_ = CandidateIndicatorComposition()
        candidate_indicator_composition_.operator = candidate_indc_comp_dict.get('operator')
        if candidate_indc_comp_dict.get('behavior_references') is not None:
            for behavior_reference_dict in candidate_indc_comp_dict.get('behavior_references'):
                candidate_indicator_composition_.behavior_references.append(BehaviorReference.from_dict(behavior_reference_dict))
        if candidate_indc_comp_dict.get('action_references') is not None:
            for action_reference_dict in candidate_indc_comp_dict.get('action_references'):
                candidate_indicator_composition_.action_references.append(ActionReference.from_dict(action_reference_dict))
        if candidate_indc_comp_dict.get('object_references') is not None:
            for object_reference_dict in candidate_indc_comp_dict.get('object_references'):
                candidate_indicator_composition_.object_references.append(ObjectReference.from_dict(object_reference_dict))
        if candidate_indc_comp_dict.get('sub_compositions') is not None:
            for sub_composition_dict in candidate_indc_comp_dict.get('sub_compositions'):
                candidate_indicator_composition_.sub_compositions.append(CandidateIndicatorComposition.from_dict(sub_composition_dict))
        return candidate_indicator_composition_

    @staticmethod
    def from_obj(candidate_indc_comp_obj):
        if not candidate_indc_comp_obj:
            return None
        candidate_indicator_composition_ = CandidateIndicatorComposition()
        candidate_indicator_composition_.operator = candidate_indc_comp_obj.get_operator()
        if len(candidate_indc_comp_obj.get_Behavior_Reference()) > 0:
            for behavior_reference_obj in candidate_indc_comp_obj.get_Behavior_Reference():
                candidate_indicator_composition_.behavior_references.append(BehaviorReference.from_obj(behavior_reference_obj))
        if len(candidate_indc_comp_obj.get_Action_Reference()) > 0:
            for action_reference_obj in candidate_indc_comp_obj.get_Action_Reference():
                candidate_indicator_composition_.action_references.append(ActionReference.from_obj(action_reference_obj))
        if len(candidate_indc_comp_obj.get_Object_Reference()) > 0:
            for object_reference_obj in candidate_indc_comp_obj.get_Object_Reference():
                candidate_indicator_composition_.object_references.append(ObjectReference.from_obj(object_reference_obj))
        if len(candidate_indc_comp_obj.get_Sub_Composition()) > 0:
            for sub_composition_obj in candidate_indc_comp_obj.get_Sub_Composition():
                candidate_indicator_composition_.sub_compositions.append(CandidateIndicatorComposition.from_obj(sub_composition_obj))
        return candidate_indicator_composition_

class CandidateIndicatorList(maec.EntityList):
    _contained_type = CandidateIndicator
    _binding_class = bundle_binding.CandidateIndicatorListType
    _binding_var = "Candidate_Indicator"