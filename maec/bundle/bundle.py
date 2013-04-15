#MAEC Bundle Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 04/10/2013

import maec.bindings.maec_bundle_3_0 as bundle_binding
import datetime
from maec.bundle.malware_action import MalwareAction
#from maec.bundle.behavior import Behavior
       
class Bundle(object):
    def __init__(self, id, generator, schema_version, defined_subject, content_type = None, malware_instance_object = None):
        if id is not None:
            self.id = id
        elif generator is not None:
            self.generator = generator
            self.id = self.generator.generate_bundle_id()
        else:
            raise Exception("Must specify id or generator for Bundle constructor")
        self.schema_version = schema_version
        self.defined_subject = defined_subject
        self.content_type = content_type
        self.malware_instance_object = malware_instance_object
        #Add all of the top-level containers
        self.actions = []
        self.process_tree = None
        self.behaviors = []
        self.objects = []
        self.candidate_indicators = []
        self.collections = []
        #Add the collection dictionaries
        self.action_collections = {}
        self.object_collections = {}
        self.behavior_collections = {}
        self.candidate_indicator_collections = {}


    #Set the Malware Instance Object Attributes
    def set_malware_instance_object_atttributes(self, malware_instance_object):
        self.malware_instance_object = malware_instance_object

    #Set the Process Tree, in the top-level <Process_Tree> element
    def set_process_tree(self, process_tree):
        self.process_tree = process_tree
        
    #Add an Action to an existing collection; if it does not exist, add it to the top-level <Actions> element
    def add_action(self, action, action_collection_name = None):
        if action_collection_name is not None:
            #The collection has already been defined
            if self.action_collections.has_key(action_collection_name):
                action_collection = self.action_collections.get(action_collection_name)
                action_collection.add_action(action)
            #The collection has not already been defined
            else:
                action_collection = ActionCollection(action_collection_name, None, self.generator)
                action_collection.add_action(action)
                self.action_collections[action_collection_name] = action_collection
        elif action_collection_name == None:
            self.actions.append(action)
                                      
    #Add an Object to an existing collection; if it does not exist, add it to the top-level <Objects> element
    def add_object(self, object, object_collection_name = None):
        if object_collection_name is not None:
            #The collection has already been defined
            if self.object_collections.has_key(object_collection_name):
                object_collection = self.object_collections.get(object_collection_name)
                object_collection.add_object(object)
            #The collection has not already been defined
            else:
                object_collection = ObjectCollection(object_collection_name, None, self.generator)
                object_collection.add_object(object)
                self.object_collections[object_collection_name] = object_collection
        elif object_collection_name == None:
            self.objects.append(object)

    #Add an Behavior to an existing collection; if it does not exist, add it to the top-level <Behaviors> element
    def add_behavior(self, behavior, behavior_collection_name = None):
        if behavior_collection_name is not None:
            #The collection has already been defined
            if self.behavior_collections.has_key(behavior_collection_name):
                behavior_collection = self.behavior_collections.get(behavior_collection_name)
                behavior_collection.add_Behavior(behavior)
            #The collection has not already been defined
            else:
                behavior_collection = BehaviorCollection(behavior_collection_name, None, self.generator)
                behavior_collection.add_Behavior(behavior)
                self.behavior_collections[behavior_collection_name] = behavior_collection
        elif behavior_collection_name == None:
            self.behaviors.append(behavior)

    #Add a Candidate Indicator to an existing collection; if it does not exist, add it to the top-level <Candidate_Indicators> element
    def add_candidate_indicator(self, candidate_indicator, candidate_indicator_collection_name = None):
        if candidate_indicator_collection_name is not None:
            #The collection has already been defined
            if self.candidate_indicator_collections.has_key(candidate_indicator_collection_name):
                candidate_indicator_collection = self.candidate_indicator_collections.get(candidate_indicator_collection_name)
                candidate_indicator_collection.add_candidate_indicator(candidate_indicator)
            #The collection has not already been defined
            else:
                candidate_indicator_collection = CandidateIndicatorCollection(candidate_indicator_collection_name, None, self.generator)
                candidate_indicator_collection.add_candidate_indicator(candidate_indicator)
                self.candidate_indicator_collections[candidate_indicator_collection_name] = candidate_indicator_collection
        elif candidate_indicator_collection_name == None:
            self.candidate_indicators.append(candidate_indicator)
                                   
    #Add a namespace to the namespaces list
    def add_namespace(self, namespace_prefix, namespace):
        if namespace_prefix not in self.namespace_prefixes.keys():
            self.namespace_prefixes[namespace_prefix] = '"' + namespace + '"'

    #Add a schemalocation to the schemalocation list
    def add_schemalocation(self, namespace, schemalocation):
        if namespace not in self.schemalocations.keys():
            self.schemalocations[namespace] = schemalocation
    
    def to_obj(self):
        bundle_obj = bundle_binding.BundleType(id=self.id)
        #Set the bundle schema version
        bundle_obj.set_schema_version(self.schema_version)
        #Set the bundle timestamp
        bundle_obj.set_timestamp(datetime.datetime.now().isoformat())
        #Set whether this Bundle has a defined_subject
        bundle_obj.set_defined_subject(self.defined_subject)
        #Set the content_type if it is not none
        if self.content_type is not None: self.bundle.set_content_type(content_type)
        #Set the Malware Instance Object Attributes (a CybOX object) if they are not none
        if self.malware_instance_object is not None: self.bundle.set_Malware_Instance_Attributes(malware_instance_object.to_obj())
        #Add the Behaviors
        if len(self.behaviors) > 0: 
            behavior_list_obj = bundle_binding.BehaviorListType()
            for behavior in self.behaviors: behavior_list_obj.add_Behavior(behavior.to_obj())
            bundle_obj.set_Behaviors(behavior_list_obj)
        #Add the Actions
        if len(self.actions) > 0: 
            action_list_obj = bundle_binding.ActionListType()
            for action in self.actions: action_list_obj.add_Action(action.to_obj())
            bundle_obj.set_Actions(action_list_obj)
        #Add the Objects
        if len(self.objects) > 0: 
            object_list_obj = bundle_binding.ObjectListType()
            for object in self.objects: object_list_obj.add_Object(object.to_obj())
            bundle_obj.set_Objects(object_list_obj)
        #Add the Process Tree
        if self.process_tree is not None: bundle_obj.set_Process_Tree(self.process_tree.to_obj())
        #Add the Candidate Indicators
        if len(self.candidate_indicators) > 0: 
            candidate_indicator_list_obj = bundle_binding.CandidateIndicatorListType()
            for candidate_indicator in self.candidate_indicators: candidate_indicator_list_obj.add_Candidate_Indicator(candidate_indicator.to_obj())
            bundle_obj.set_Candidate_Indicators(candidate_indicator_list_obj)
        #Add the particular Collection types, if applicable
        collections_obj = bundle_binding.CollectionsType()
        if len(self.action_collections) > 0:
            action_collection_list = bundle_binding.ActionCollectionListType()
            for action_collection in self.action_collections.values():
                action_collection_list.add_Action_Collection(action_collection.to_obj())
            collections_obj.set_Action_Collections(action_collection_list)
        if len(self.object_collections) > 0:
            object_collection_list = bundle_binding.ObjectCollectionListType()
            for object_collection in self.object_collections.values():
                object_collection_list.add_Object_Collection(object_collection.to_obj())
            collections_obj.set_Object_Collections(object_collection_list)
        if len(self.behavior_collections) > 0:
            behavior_collection_list = bundle_binding.BehaviorCollectionListType()
            for behavior_collection in self.behavior_collections.values():
                behavior_collection_list.add_Behavior_Collection(behavior_collection.to_obj())
            collections_obj.set_Behavior_Collections(behavior_collection_list)
        if len(self.candidate_indicator_collections) > 0:
            candidate_indicator_collection_list = bundle_binding.CandidateIndicatorCollectionListType()
            for candidate_indicator_collection in self.candidate_indicator_collections.values():
                candidate_indicator_collection_list.add_Candidate_Indicator_Collection(candidate_indicator_collection.to_obj())
            collections_obj.set_Candidate_Indicator_Collections(candidate_indicator_collection_list)
        #Add the Collections
        if collections_obj.hasContent_(): bundle_obj.set_Collections(collections_obj)

        return bundle_obj

    def to_dict(self):
        pass

    @staticmethod
    def from_obj(bundle_obj):
        pass

    @staticmethod
    def from_dict(bundle_dict):
        pass

class BaseCollection(object):
    def __init__(self, name = None):
        self.name = name
        self.affinity_type = None
        self.affinity_degree = None
        self.description = None

    def to_obj(self, derived_collection_obj = None):
        if derived_collection_obj == None:
            collection_obj = bundle_binding.BaseCollectionType()
        else:
            collection_obj = derived_collection_obj
        if self.name is not None: collection_obj.set_name(self.name)
        if self.affinity_type is not None: collection_obj.set_Affinity_Type(self.affinity_type)
        if self.affinity_degree is not None: collection_obj.set_Affinity_Degree(self.affinity_degree)               
        if self.description is not None: collection_obj.set_Description(self.description)
        return collection_obj

    def to_dict(self):
        pass

    @staticmethod
    def from_obj(collection_obj):
        pass

    @staticmethod
    def from_dict(collection_dict, derived_collection_cls = None):
        if not collection_dict:
            return None
        if derived_collection_cls == None:
            collection_obj_ = BaseCollection()
        else:
            collection_obj_ = derived_collection_cls
        collection_obj_.name = collection_dict.get('name')
        collection_obj_.affinity_type = collection_dict.get('affinity_type')
        collection_obj_.affinity_degree = collection_dict.get('affinity_degree')
        collection_obj_.description = collection_dict.get('description')
        return collection_obj_

class ActionCollection(BaseCollection):
    superclass = BaseCollection

    def __init__(self, name = None, id = None, generator = None):
        super(ActionCollection, self).__init__(name)
        self.id = id
        self.actions = []
        self.generator = generator

    def add_action(self, action):
        self.actions.append(action)

    def to_obj(self):
        action_collection_obj = super(ActionCollection, self).to_obj(bundle_binding.ActionCollectionType())
        if self.id == None:
            action_collection_obj.set_id(self.generator.generate_action_collection_id())
        else:
            action_collecton_obj.set_id(self.id)
        if self.actions is not None: 
            action_list_obj = bundle_binding.ActionListType()
            for action in self.actions:
                action_list_obj.add_Action(action.to_obj())
            action_collection_obj.set_Action_List(action_list_obj)
        return action_collection_obj

    def to_dict(self):
        pass

    @staticmethod
    def from_obj(action_collection_obj):
        pass

    @staticmethod
    def from_dict(action_collection_dict):
        if not action_collection_dict:
            return action_collection_dict
        action_collection_ = BaseCollection.from_dict(action_collection_dict, ActionCollection())
        action_collection_.id = action_collection_dict.get('id')
        action_collection_.actions = [MalwareAction.from_dict(x) for x in action_collection_dict.get('action_list')]
        return action_collection_

class BehaviorCollection(BaseCollection):
    superclass = BaseCollection

    def __init__(self, name = None, id = None, generator = None):
        super(BehaviorCollection, self).__init__(name)
        self.id = id
        self.behaviors = []
        self.generator = generator

    def add_behavior(self, behavior):
        self.behaviors.append(behavior)

    def to_obj(self):
        behavior_collection_obj = super(BehaviorCollection, self).to_obj(bundle_binding.BehaviorCollectionType())
        if self.id == None:
            behavior_collection_obj.set_id(self.generator.generate_behavior_collection_id())
        else:
            behavior_collection_obj.set_id(self.id)
        if self.behaviors is not None: 
            behavior_list_obj = bundle_binding.BehaviorListType()
            for behavior in self.behaviors:
                behavior_list_obj.add_Behavior(behavior.to_obj())
            behavior_collection_obj.set_Behavior_List(behavior_list_obj)
        return behavior_collection_obj

    def to_dict(self):
        pass

    @staticmethod
    def from_obj(behavior_collection_obj):
        pass

    @staticmethod
    def from_dict(behavior_collection_dict):
        if not behavior_collection_dict:
            return None
        behavior_collection_ = BaseCollection.from_dict(behavior_collection_dict, BehaviorCollection())
        behavior_collection_.id = behavior_collection_dict.get('id')
        behavior_collection_.behaviors = [Behavior.from_dict(x) for x in behavior_collection_dict.get('behavior_list')]
        return behavior_collection_

class ObjectCollection(BaseCollection):
    superclass = BaseCollection

    def __init__(self, name = None, id = None, generator = None):
        super(ObjectCollection, self).__init__(name)
        self.id = id
        self.objects = []
        self.generator = generator

    def add_object(self, object):
        self.objects.append(object)

    def to_obj(self):
        object_collection_obj = super(ObjectCollection, self).to_obj(bundle_binding.ObjectCollectionType())
        if self.id == None:
            object_collection_obj.set_id(self.generator.generate_object_collection_id())
        else:
            object_collection_obj.set_id(self.id)
        if self.objects is not None: 
            object_list_obj = bundle_binding.ObjectListType()
            for object in self.objects:
                object_list_obj.add_Object(Object.to_obj())
            object_collection_obj.set_Object_List(object_list_obj)
        return object_collection_obj

    def to_dict(self):
        pass

    @staticmethod
    def from_obj(object_collection_obj):
        pass

    @staticmethod
    def from_dict(object_collection_dict):
        if not object_collection_dict:
            return None
        object_collection_ = BaseCollection.from_dict(object_collection_dict, ObjectCollection())
        object_collection_.id = behavior_collection_dict.get('id')
        object_collection_.objects = [Object.from_dict(x) for x in object_collection_dict.get('object_list')]
        return object_collection_

class CandidateIndicatorCollection(BaseCollection):
    superclass = BaseCollection

    def __init__(self, name = None, id = None, generator = None):
        super(CandidateIndicatorCollection, self).__init__(name)
        self.id = id
        self.candidate_indicators = []
        self.generator = generator

    def add_candidate_indicator(self, candidate_indicator):
        self.candidate_indicators.append(candidate_indicator)

    def to_obj(self):
        candidate_indicator_collection_obj = super(CandidateIndicatorCollection, self).to_obj(bundle_binding.CandidateIndicatorCollectionType())
        if self.id == None:
            candidate_indicator_collection_obj.set_id(self.generator.generate_candidate_indicator_collection_id())
        else:
            candidate_indicator_collection_obj.set_id(self.id)
        if self.candidate_indicators is not None: 
            candidate_indicator_list_obj = bundle_binding.CandidateIndicatorListType()
            for candidate_indicator in self.candidate_indicators:
                candidate_indicator_list_obj.add_Candidate_Indicator(Candidate_Indicator.to_obj())
            candidate_indicator_collection_obj.set_Candidate_Indicator_List(candidate_indicator_list_obj)
        return candidate_indicator_collection_obj

    def to_dict(self):
        pass

    @staticmethod
    def from_obj(candidate_indicator_collection_obj):
        pass

    @staticmethod
    def from_dict(candidate_indicator_collection_dict):
        if not candidate_indicator_collection_dict:
            return None
        candidate_indicator_collection_ = BaseCollection.from_dict(candidate_indicator_collection_dict, CandidateIndicatorCollection())
        candidate_indicator_collection_.id = candidate_indicator_collection_dict.get('id')
        candidate_indicator_collection_.candidate_indicators = [CandidateIndicator.from_dict(x) for x in candidate_indicator_collection_dict.get('candidate_indicator_list')]
        return candidate_indicator_collection_
