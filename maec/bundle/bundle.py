# MAEC Bundle Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

from cybox.core import Object
from cybox.utils.normalize import normalize_object_properties

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle import (MalwareAction, AVClassifications, Behavior,
                         CandidateIndicatorList, ProcessTree, CapabilityList,
                         ObjectHistory)
from maec.utils import BundleComparator, BundleDeduplicator


class BehaviorList(maec.EntityList):
    _contained_type = Behavior
    _binding_class = bundle_binding.BehaviorListType
    _binding_var = "Behavior"
    _namespace = _namespace

class ActionList(maec.EntityList):
    _contained_type = MalwareAction
    _binding_class = bundle_binding.ActionListType
    _binding_var = "Action"
    _namespace = _namespace
    
class ObjectList(maec.EntityList):
    _contained_type = Object
    _binding_class = bundle_binding.ObjectListType
    _binding_var = "Object"
    _namespace = _namespace

class BaseCollection(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BaseCollectionType
    _namespace = _namespace

    name = fields.TypedField("name")
    affinity_type = fields.TypedField("Affinity_Type")
    affinity_degree = fields.TypedField("Affinity_Degree")
    description = fields.TypedField("Description")

    def __init__(self, name = None):
        super(BaseCollection, self).__init__()
        self.name = name

class ActionCollection(BaseCollection):
    _binding = bundle_binding
    _binding_class = bundle_binding.ActionCollectionType
    _namespace = _namespace

    id_ = fields.TypedField("id")
    action_list = fields.TypedField("Action_List", ActionList)

    def __init__(self, name = None, id = None):
        super(ActionCollection, self).__init__(name)
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="action_collection")
        self.action_list = ActionList()

    def add_action(self, action):
        """Add an input Action to the Collection."""
        self.action_list.append(action)

class BehaviorCollection(BaseCollection):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehaviorCollectionType
    _namespace = _namespace

    id_ = fields.TypedField("id")
    behavior_list = fields.TypedField("Behavior_List", BehaviorList)

    def __init__(self, name = None, id = None):
        super(BehaviorCollection, self).__init__(name)
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="behavior_collection")
        self.behavior_list = BehaviorList()

    def add_behavior(self, behavior):
        """Add an input Behavior to the Collection."""
        self.behavior_list.append(behavior)

class ObjectCollection(BaseCollection):
    _binding = bundle_binding
    _binding_class = bundle_binding.ObjectCollectionType
    _namespace = _namespace

    id_ = fields.TypedField("id")
    object_list = fields.TypedField("Object_List", ObjectList)

    def __init__(self, name = None, id = None):
        super(ObjectCollection, self).__init__(name)
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="object_collection")
        self.object_list = ObjectList()

    def add_object(self, object):
        """Add an input Object to the Collection."""
        self.object_list.append(object)

class CandidateIndicatorCollection(BaseCollection):
    _binding = bundle_binding
    _binding_class = bundle_binding.CandidateIndicatorCollectionType
    _namespace = _namespace

    id_ = fields.TypedField("id")
    candidate_indicator_list = fields.TypedField("Candidate_Indicator_List", CandidateIndicatorList)

    def __init__(self, name = None, id = None):
        super(CandidateIndicatorCollection, self).__init__(name)
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="candidate_indicator_collection")
        self.candidate_indicator_list = CandidateIndicatorList()

    def add_candidate_indicator(self, candidate_indicator):
        """Add an input Candidate Indicator to the Collection."""
        self.candidate_indicator_list.append(candidate_indicator)

class BehaviorCollectionList(maec.EntityList):
    _contained_type = BehaviorCollection
    _binding_class = bundle_binding.BehaviorCollectionListType
    _binding_var = "Behavior_Collection"
    _namespace = _namespace

    def __init__(self):
        super(BehaviorCollectionList, self).__init__()

    def to_obj(self, return_obj=None, ns_info=None):
        self._collect_ns_info(ns_info)

        behavior_collection_list_obj = bundle_binding.BehaviorCollectionListType()
        for behavior_collection in self:
            if len(behavior_collection.behavior_list) > 0:
                behavior_collection_list_obj.add_Behavior_Collection(behavior_collection.to_obj(ns_info=ns_info))
        if behavior_collection_list_obj.hasContent_():
            return behavior_collection_list_obj

    def has_collection(self, collection_name):
        """Checks for the existence of a specific named Collection in the list, based on the its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return True
        return False

    def get_named_collection(self, collection_name):
        """Return a specific named Collection from the list, based on its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return collection
        return None

class ActionCollectionList(maec.EntityList):
    _contained_type = ActionCollection
    _binding_class = bundle_binding.ActionCollectionListType
    _binding_var = "Action_Collection"
    _namespace = _namespace

    def __init__(self):
        super(ActionCollectionList, self).__init__()

    def to_obj(self, return_obj=None, ns_info=None):
        self._collect_ns_info(ns_info)

        action_collection_list_obj = bundle_binding.ActionCollectionListType()
        for action_collection in self:
            if len(action_collection.action_list) > 0:
                action_collection_list_obj.add_Action_Collection(action_collection.to_obj(ns_info=ns_info))
        if action_collection_list_obj.hasContent_():
            return action_collection_list_obj

    def has_collection(self, collection_name):
        """Checks for the existence of a specific named Collection in the list, based on the its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return True
        return False

    def get_named_collection(self, collection_name):
        """Return a specific named Collection from the list, based on its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return collection
        return None

class ObjectCollectionList(maec.EntityList):
    _contained_type = ObjectCollection
    _binding_class = bundle_binding.ObjectCollectionListType
    _binding_var = "Object_Collection"
    _namespace = _namespace

    def __init__(self):
        super(ObjectCollectionList, self).__init__()

    def to_obj(self, return_obj=None, ns_info=None):
        self._collect_ns_info(ns_info)

        object_collection_list_obj = bundle_binding.ObjectCollectionListType()
        for object_collection in self:
            if len(object_collection.object_list) > 0:
                object_collection_list_obj.add_Object_Collection(object_collection.to_obj(ns_info=ns_info))
        if object_collection_list_obj.hasContent_():
            return object_collection_list_obj

    def has_collection(self, collection_name):
        """Checks for the existence of a specific named Collection in the list, based on the its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return True
        return False

    def get_named_collection(self, collection_name):
        """Return a specific named Collection from the list, based on its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return collection
        return None

class CandidateIndicatorCollectionList(maec.EntityList):
    _contained_type = CandidateIndicatorCollection
    _binding_class = bundle_binding.CandidateIndicatorCollectionListType
    _binding_var = "Candidate_Indicator_Collection"
    _namespace = _namespace

    def __init__(self):
        super(CandidateIndicatorCollectionList, self).__init__()

    def to_obj(self, return_obj=None, ns_info=None):
        self._collect_ns_info(ns_info)

        candidate_indicator_collection_list_obj = bundle_binding.CandidateIndicatorCollectionListType()
        for candidate_indicator_collection in self:
            if len(candidate_indicator_collection.candidate_indicator_list) > 0:
                candidate_indicator_collection_list_obj.add_Candidate_Indicator_Collection(candidate_indicator_collection.to_obj(ns_info=ns_info))
        if candidate_indicator_collection_list_obj.hasContent_():
            return candidate_indicator_collection_list_obj

    def has_collection(self, collection_name):
        """Checks for the existence of a specific named Collection in the list, based on the its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return True
        return False

    def get_named_collection(self, collection_name):
        """Return a specific named Collection from the list, based on its name."""
        for collection in self:
            if collection.name is not None and collection.name == collection_name:
                return collection
        return None

class Collections(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.CollectionsType
    _namespace = _namespace

    behavior_collections = fields.TypedField("Behavior_Collections", BehaviorCollectionList)
    action_collections = fields.TypedField("Action_Collections", ActionCollectionList)
    object_collections = fields.TypedField("Object_Collections", ObjectCollectionList)
    candidate_indicator_collections = fields.TypedField("Candidate_Indicator_Collections", CandidateIndicatorCollectionList)

    def __init__(self):
        super(Collections, self).__init__()

    def add_named_action_collection(self, action_collection_name, collection_id = None):
        """Add a new named Action Collection to the Collections instance."""
        if not self.action_collections:
            self.action_collections = ActionCollectionList()
        self.action_collections.append(ActionCollection(action_collection_name, collection_id))

    def add_named_object_collection(self, object_collection_name, collection_id = None):
        """Add a new named Object Collection to the Collections instance."""
        if not self.object_collections:
            self.object_collections = ObjectCollectionList()
        self.object_collections.append(ObjectCollection(object_collection_name, collection_id))

    def add_named_behavior_collection(self, behavior_collection_name, collection_id = None):
        """Add a new named Behavior Collection to the Collections instance."""
        if not self.behavior_collections:
            self.behavior_collections = BehaviorCollectionList()
        self.behavior_collections.append(BehaviorCollection(behavior_collection_name, collection_id))

    def add_named_candidate_indicator_collection(self, candidate_indicator_collection_name, collection_id = None):
        """Add a new named Candidate Indicator Collection to the Collections instance."""
        if not self.candidate_indicator_collections:
            self.candidate_indicator_collections = CandidateIndicatorCollectionList()
        self.candidate_indicator_collections.append(CandidateIndicatorCollection(candidate_indicator_collection_name, collection_id))

    def has_content(self):
        """Returns true if any Collections instance inside of the Collection has len > 0."""
        if self.behavior_collections and len(self.behavior_collections) > 0:
            return True
        elif self.action_collections and len(self.action_collections) > 0:
            return True
        elif self.object_collections and len(self.object_collections) > 0:
            return True
        elif self.candidate_indicator_collections and len(self.candidate_indicator_collections) > 0:
            return True
        return False

class BehaviorReference(maec.Entity):
    _binding = bundle_binding
    _binding_class = bundle_binding.BehaviorReferenceType
    _namespace = _namespace

    behavior_idref = fields.TypedField('behavior_idref')

class Bundle(maec.Entity):
    _binding = bundle_binding
    _namespace = _namespace
    _binding_class = bundle_binding.BundleType

    id_ = fields.TypedField("id")
    schema_version = fields.TypedField("schema_version")
    defined_subject = fields.TypedField("defined_subject")
    content_type = fields.TypedField("content_type")
    timestamp = fields.TypedField("timestamp")
    malware_instance_object_attributes = fields.TypedField("Malware_Instance_Object_Attributes", Object)
    av_classifications = fields.TypedField("AV_Classifications", AVClassifications)
    actions = fields.TypedField("Actions", ActionList)
    process_tree = fields.TypedField("Process_Tree", ProcessTree)
    behaviors = fields.TypedField("Behaviors", BehaviorList)
    capabilities = fields.TypedField("Capabilities", CapabilityList)
    objects = fields.TypedField("Objects", ObjectList)
    candidate_indicators = fields.TypedField("Candidate_Indicators", CandidateIndicatorList)
    collections = fields.TypedField("Collections", Collections)

    def __init__(self, id = None, defined_subject = False, schema_version = "4.1", content_type = None, malware_instance_object = None):
        super(Bundle, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="bundle")
        self.schema_version = schema_version
        self.defined_subject = defined_subject
        self.content_type = content_type
        self.timestamp = None
        self.malware_instance_object_attributes = malware_instance_object
        self.__input_namespaces__ = {}
        self.__input_schemalocations__ = {}

    def set_malware_instance_object_attributes(self, malware_instance_object):
        """Set the top-level Malware Instance Object Attributes entity in the Bundle."""
        self.malware_instance_object_attributes = malware_instance_object

    def add_av_classification(self, av_classification):
        """Add an AV Classification to the top-level AV_Classifications entity in the Bundle."""
        if not self.av_classifications:
            self.av_classifications = AVClassifications()
        self.av_classifications.append(av_classification)

    def add_capability(self, capability):
        """Add a Capability to the top-level Capabilities entity in the Bundle."""
        if not self.capabilities:
            self.capabilities = CapabilityList()
        self.capabilities.capability.append(capability)

    def set_process_tree(self, process_tree):
        """Set the Process Tree, in the top-level <Process_Tree> element."""
        self.process_tree = process_tree

    def add_named_action_collection(self, collection_name, collection_id = None):
        """Add a new named Action Collection to the top-level Collections entity in the Bundle."""
        if not self.collections:
            self.collections = Collections()
        if collection_name is not None:
            self.collections.add_named_action_collection(collection_name, collection_id)
        
    def add_action(self, action, action_collection_name = None):
        """Add an Action to an existing named Action Collection in the Collections entity. 
           If it does not exist, add it to the top-level Actions entity."""
        if action_collection_name is not None and self.collections:
            #The collection has already been defined
            if self.collections.action_collections.has_collection(action_collection_name):
                action_collection = self.collections.action_collections.get_named_collection(action_collection_name)
                action_collection.add_action(action)
        elif action_collection_name == None:
            if not self.actions:
                self.actions = ActionList()
            self.actions.append(action)

    def add_named_object_collection(self, collection_name, collection_id = None):
        """Add a new named Object Collection to the Collections entity in the Bundle."""
        if not self.collections:
            self.collections = Collections()
        if collection_name is not None:
            self.collections.add_named_object_collection(collection_name, collection_id)
              
    def get_all_actions(self, bin = False):
        """Return a list of all Actions in the Bundle."""
        all_actions = []

        if self.actions:
            for action in self.actions:
                all_actions.append(action)
            
        if self.collections and self.collections.action_collections:
            for collection in self.collections.action_collections:
                for action in collection.action_list:
                    all_actions.append(action)

        if bin:
            binned_actions = {}
            for action in all_actions:
                if action.name and action.name.value not in binned_actions:
                    binned_actions[action.name.value] = [action]
                elif action.name and action.name.value in binned_actions:
                    binned_actions[action.name.value].append(action)
            return binned_actions
        else:
            return all_actions

    def get_all_actions_on_object(self, object):
        """Return a list of all of the Actions in the Bundle that operate on a particular input Object."""
        object_actions = []
        if object.id_:
            for action in self.get_all_actions():
                associated_objects = action.associated_objects
                if associated_objects:
                    for associated_object in associated_objects:
                        if associated_object.idref and associated_object.idref == object.id_:
                            object_actions.append(action)
                        elif associated_object.id_ and associated_object.id_ == object.id_:
                            object_actions.append(action)
            return object_actions

    def add_object(self, object, object_collection_name = None):
        """Add an Object to an existing named Object Collection in the Collections entity. 
           If it does not exist, add it to the top-level Object entity."""
        if object_collection_name is not None and self.collections:
            #The collection has already been defined
            if self.collections.object_collections.has_collection(object_collection_name):
                object_collection = self.collections.object_collections.get_named_collection(object_collection_name)
                object_collection.add_object(object)
        elif object_collection_name == None:
            if not self.objects:
                self.objects = ObjectList()
            self.objects.append(object)

    def get_all_objects(self, include_actions = False):
        """Return a list of all Objects in the Bundle."""
        all_objects = []

        if self.objects:
            for obj in self.objects:
                all_objects.append(obj)
                if obj.related_objects:
                    for related_obj in obj.related_objects:
                        all_objects.append(related_obj)
            
        if self.collections and self.collections.object_collections:
            for collection in self.collections.object_collections:
                for obj in collection.object_list:
                    all_objects.append(obj)
                    if obj.related_objects:
                        for related_obj in obj.related_objects:
                            all_objects.append(related_obj)

        # Include Objects in Actions, if include_actions flag is specified
        if include_actions:
            for action in self.get_all_actions():
                associated_objects = action.associated_objects
                if associated_objects:
                    for associated_object in associated_objects:
                        all_objects.append(associated_object)
                        if associated_object.related_objects:
                            for related_obj in associated_object.related_objects:
                                all_objects.append(related_obj)

        # Add the Object corresponding to the Malware Instance Object Attributes, if specified
        if self.malware_instance_object_attributes:
            all_objects.append(self.malware_instance_object_attributes)

        return all_objects

    def get_all_multiple_referenced_objects(self):
        """Return a list of all Objects in the Bundle that are referenced more than once."""
        idref_list = [x.idref for x in self.get_all_objects() if x.idref]
        return [self.get_object_by_id(x) for x in idref_list if self.get_object_by_id(x)]

    def get_all_non_reference_objects(self):
        """Return a list of all Objects in the Bundle that are not references (i.e. all of the actual Objects in the Bundle)."""
        return [x for x in self.get_all_objects(True) if x.id_ and not x.idref]

    def get_object_by_id(self, id, extra_objects = [], ignore_actions = False):
        """Find and return the Entity (Action, Object, etc.) with the specified ID."""
        if not ignore_actions:
            if self.actions:
                for action in self.actions:
                    if action.id_ == id:
                        return action
            
                    if action.associated_objects:
                        for associated_obj in action.associated_objects:
                            if associated_obj.id_ == id:
                                return associated_obj
            if self.collections and self.collections.action_collections:
                for collection in self.collections.action_collections:
                    for action in collection.action_list:
                        if action.id_ == id:
                            return action
                
                        if action.associated_objects:
                            for associated_obj in action.associated_objects:
                                if associated_obj.id_ == id:
                                    return associated_obj
        if self.objects:
            for obj in self.objects:
                if obj.id_ == id:
                    return obj

        if self.collections and self.collections.object_collections:   
            for collection in self.collections.object_collections:
                for obj in collection.object_list:
                    if obj.id_ == id:
                        return obj

        # Test the extra_objects Array
        for obj in extra_objects:
            if obj.id_ == id:
                return obj

    def add_named_behavior_collection(self, collection_name, collection_id = None):
        """Add a new named Behavior Collection to the Collections entity in the Bundle."""
        if not self.collections:
            self.collections = Collections()
        if collection_name is not None:
            self.collections.add_named_behavior_collection(collection_name, collection_id)

    def add_behavior(self, behavior, behavior_collection_name = None):
        """Add a Behavior to an existing named Behavior Collection in the Collections entity. 
           If it does not exist, add it to the top-level Behaviors entity."""
        if behavior_collection_name is not None and self.collections:
            #The collection has already been defined
            if self.collections.behavior_collections.has_collection(behavior_collection_name):
                behavior_collection = self.collections.behavior_collections.get_named_collection(behavior_collection_name)
                behavior_collection.add_Behavior(behavior)
        elif behavior_collection_name == None:
            if not self.behaviors:
                self.behaviors = BehaviorList()
            self.behaviors.append(behavior)

    def add_named_candidate_indicator_collection(self, collection_name, collection_id = None):
        """Add a new named Candidate Indicator Collection to the Collections entity in the Bundle."""
        if not self.collections():
            self.collections = Collections()
        if collection_name is not None and collection_id is not None:
            self.collections.add_named_candidate_indicator_collection(collection_name, collection_id)

    def add_candidate_indicator(self, candidate_indicator, candidate_indicator_collection_name = None):
        """Add a Candidate Indicator to an existing named Candidate Indicator Collection in the Collections entity. 
           If it does not exist, add it to the top-level Candidate Indicators entity."""
        if candidate_indicator_collection_name is not None and self.collections:
            #The collection has already been defined
            if self.collections.candidate_indicator_collections.has_collection(candidate_indicator_collection_name):
                candidate_indicator_collection = self.collections.candidate_indicator_collections.get_named_collection(candidate_indicator_collection_name)
                candidate_indicator_collection.add_candidate_indicator(candidate_indicator)
        elif candidate_indicator_collection_name == None:
            if not self.candidate_indicators:
                self.candidate_indicators = CandidateIndicatorList()
            self.candidate_indicators.append(candidate_indicator)
    
    def deduplicate(self):
        """Deduplicate all Objects in the Bundle. 
           Add duplicate Objects to new "Deduplicated Objects" Object Collection,
           and replace duplicate entries with references to corresponding Object."""
        BundleDeduplicator.deduplicate(self)

    def get_action_objects(self, action_name_list):
        """Get all Objects corresponding to one or more types of Actions, specified via a list of Action names."""
        action_objects = {}
        all_actions = self.get_all_actions(bin=True)
        for action_name in action_name_list:
            if action_name in all_actions:
                associated_objects = []
                associated_object_lists = [[y for y in x.associated_objects if x.associated_objects] for x in all_actions[action_name]]
                for associated_object_list in associated_object_lists:
                    associated_objects += associated_object_list
                action_objects[action_name] = associated_objects
        return action_objects

    def get_object_history(self):
        """Build and return the Object history for the Bundle."""
        return ObjectHistory.build(self)

    def normalize_objects(self):
        """Normalize all Objects in the Bundle, using the CybOX normalize module."""
        all_objects = self.get_all_objects(include_actions = True)
        for object in all_objects:
            if object.properties:
                normalize_object_properties(object.properties)

    def dereference_objects(self, extra_objects = []):
        """Dereference any Objects in the Bundle by replacing them with the entities they reference."""
        all_objects = self.get_all_objects(include_actions=True)
        # Add any extra objects that were passed, e.g. from a Malware Subject
        all_objects = all_objects + extra_objects
        for object in all_objects:
            if object.idref and not object.id_:
                real_object = self.get_object_by_id(object.idref, extra_objects, ignore_actions = True)
                if real_object:
                    object.idref = None
                    object.id_ = real_object.id_
                    object.properties = real_object.properties

    @classmethod
    def compare(cls, bundle_list, match_on = None, case_sensitive = True):
        """Compare the Bundle to a list of other Bundles, returning a BundleComparator object."""
        return BundleComparator.compare(bundle_list, match_on, case_sensitive)
