#MAEC Bundle Class

#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 12/28/2012

import maec_bundle_3_0 as bundle_binding
import datetime
       
class bundle:
    def __init__(self, generator, schema_version, defined_subject, content_type = None, malware_instance_object = None, bundle_attributes_dict = None):
        self.generator = generator
        #Create the MAEC Bundle object
        self.bundle = bundle_binding.BundleType(id=self.generator.generate_bnd_id())
        #Set the bundle schema version
        self.bundle.set_schema_version(schema_version)
        #Set the bundle timestamp
        self.bundle.set_timestamp(datetime.datetime.now().isoformat())
        #Set whether this Bundle has a defined_subject
        self.bundle.set_defined_subject(defined_subject)
        #Set the content_type if it is not none
        if content_type is not None:
            self.bundle.set_content_type(content_type)
        #Set the Malware Instance Object Attributes (a CybOX object) if they are not none
        if malware_instance_object is not None:
            self.bundle.set_Malware_Instance_Attributes(malware_instance_object)
        self.bundle_attributes_dict = bundle_attributes_dict
        #Add all of the top-level containers
        self.actions = bundle_binding.ActionListType()
        self.process_tree = bundle_binding.ProcessTreeType()
        self.behaviors = bundle_binding.BehaviorListType()
        self.objects = bundle_binding.ObjectListType()
        self.candidate_indicators = bundle_binding.CandidateIndicatorListType()
        self.collections = bundle_binding.CollectionsType()
        #Add the collection dictionaries
        self.action_collections = {}
        self.object_collections = {}
        self.behavior_collections = {}
        self.candidate_indicator_collections = {}
        #Create the namespace and schemalocation declarations
        self.namespace_prefixes = {'xmlns:maecBundle' : '"http://maec.mitre.org/XMLSchema/maec-bundle-3"',
                                   'xmlns:cybox' : '"http://cybox.mitre.org/cybox_v1"',
                                   'xmlns:Common' : '"http://cybox.mitre.org/Common_v1"',
                                   'xmlns:mmdef' : '"http://xml/metadataSharing.xsd"',
                                   'xmlns:xsi' : '"http://www.w3.org/2001/XMLSchema-instance"'}
        self.schemalocations = {'http://maec.mitre.org/XMLSchema/maec-package-1' : 'http://maec.mitre.org/language/version3.0/maec-package-schema.xsd',
                                'http://maec.mitre.org/XMLSchema/maec-bundle-3' :  'http://maec.mitre.org/language/version3.0/maec-bundle-schema.xsd',
                                'http://cybox.mitre.org/Common_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_common_types_v1.0.xsd',
                                'http://cybox.mitre.org/cybox_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_core_v1.0.xsd',
                                'http://xml/metadataSharing.xsd' : 'http://grouper.ieee.org/groups/malware/malwg/Schema1.2/metadataSharing.xsd'}

    #Set the Malware Instance Object Attributes
    def set_malware_instance_object_atttributes(self, malware_instance_object):
        self.bundle.set_Malware_Instance_Object_Attributes(malware_instance_object)

    #Set the Process Tree, in the top-level <Process_Tree> element
    def set_process_tree(self, process_tree):
        self.process_tree = process_tree
        
    #Add an Action to an existing collection; if it does not exist, add it to the top-level <Actions> element
    def add_action(self, action, action_collection_name = None):
        if action_collection_name is not None:
            #The collection has already been defined
            if self.action_collections.has_key(action_collection_name):
                action_collection = self.action_collections.get(action_collection_name)
                action_list = action_collection.get_Action_List()
                action_list.add_Action(action)
            #The collection has not already been defined
            else:
                action_collection = bundle_binding.ActionCollectionType(id=self.generator.generate_actc_id(), name = action_collection_name)
                action_list = bundle_binding.ActionListType()
                action_list.add_Action(action)
                action_collection.set_Action_List(action_list)
                self.action_collections[action_collection_name] = action_collection
        elif action_collection_name == None:
            self.actions.add_Action(action) 
                                      
    #Add an Object to an existing collection; if it does not exist, add it to the top-level <Objects> element
    def add_object(self, object, object_collection_name = None):
        if object_collection_name is not None:
            #The collection has already been defined
            if self.object_collections.has_key(object_collection_name):
                object_collection = self.object_collections.get(object_collection_name)
                object_list = object_collection.get_Object_List()
                object_list.add_Object(object)
            #The collection has not already been defined
            else:
                object_collection = bundle_binding.ObjectCollectionType(id=self.generator.generate_objc_id(), name = object_collection_name)
                object_list = bundle_binding.ObjectListType()
                object_list.add_Object(object)
                object_collection.set_Object_List(object_list)
                self.object_collections[object_collection_name] = object_collection
        elif object_collection_name == None:
            self.objects.add_Object(object)

    #Add an Behavior to an existing collection; if it does not exist, add it to the top-level <Behaviors> element
    def add_behavior(self, behavior, behavior_collection_name = None):
        if behavior_collection_name is not None:
            #The collection has already been defined
            if self.behavior_collections.has_key(behavior_collection_name):
                behavior_collection = self.behavior_collections.get(behavior_collection_name)
                behavior_list = behavior_collection.get_Behavior_List()
                behavior_list.add_Behavior(behavior)
            #The collection has not already been defined
            else:
                behavior_collection = bundle_binding.BehaviorCollectionType(id=self.generator.generate_bhvc_id(), name = behavior_collection_name)
                behavior_list = bundle_binding.BehaviorListType()
                behavior_list.add_Behavior(behavior)
                behavior_collection.set_Behavior_List(behavior_list)
                self.behavior_collections[behavior_collection_name] = behavior_collection
        elif behavior_collection_name == None:
            self.behaviors.add_Behavior(behavior)

    #Add a Candidate Indicator to an existing collection; if it does not exist, add it to the top-level <Candidate_Indicators> element
    def add_candidate_indicator(self, candidate_indicator, candidate_indicator_collection_name = None):
        if candidate_indicator_collection_name is not None:
            #The collection has already been defined
            if self.candidate_indicator_collections.has_key(candidate_indicator_collection_name):
                candidate_indicator_collection = self.candidate_indicator_collections.get(candidate_indicator_collection_name)
                candidate_indicator_list = candidate_indicator_collection.get_Candidate_Indicator_List()
                candidate_indicator_list.add_Candidate_Indicator(candidate_indicator)
            #The collection has not already been defined
            else:
                candidate_indicator_collection = bundle_binding.CandidateIndicatorCollectionType(id=self.generator.generate_indc_id(), name = candidate_indicator_collection_name)
                candidate_indicator_list = bundle_binding.CandidateIndicatorListType()
                candidate_indicator_list.add_Candidate_Indicator(candidate_indicator)
                candidate_indicator_collection.set_Candidate_Indicator_List(candidate_indicator_list)
                self.candidate_indicator_collections[candidate_indicator_collection_name] = candidate_indicator_collection
        elif candidate_indicator_collection_name == None:
            self.candidate_indicators.add_Candidate_Indicator(candidate_indicator)
                                   
    #Add a namespace to the namespaces list
    def add_namespace(self, namespace_prefix, namespace):
        self.namespace_prefixes[namespace_prefix] = '"' + namespace + '"'

    #Add a schemalocation to the schemalocation list
    def add_schemalocation(self, namespace, schemalocation):
        self.schemalocations[namespace] = schemalocation
    
    #Export the MAEC bundle and its contents to an XML file
    def export_to_file(self, outfilename):
        self.__build__()
        outfile = open(outfilename, 'w')
        self.bundle.export(outfile, 0, namespacedef_=self.__build_namespaces_schemalocations())
     
    #Build the Bundle from the input dictionary
    def build_from_dictionary(self):
        for key, value in self.bundle_attributes_dict.items():
            pass

    #Accessor methods
    def get(self):
        self.__build__()
        return self.bundle

    #Private methods

    #Build the MAEC bundle by adding all applicable elements
    def __build__(self):
        #Add the Behaviors
        if self.behaviors.hasContent_(): self.bundle.set_Behaviors(self.behaviors)
        #Add the Actions
        if self.actions.hasContent_(): self.bundle.set_Actions(self.behaviors)
        #Add the Objects
        if self.objects.hasContent_() : self.bundle.set_Objects(self.objects)
        #Add the Process Tree
        if self.process_tree.hasContent_(): self.bundle.set_Process_Tree(self.process_tree)
        #Add the Candidate Indicators
        if self.candidate_indicators.hasContent_(): self.bundle.set_Candidate_Indicators(self.candidate_indicators)
        #Add the particular Collection types, if applicable
        if len(self.action_collections) > 0:
            action_collection_list = bundle_binding.ActionCollectionListType()
            for action_collection in self.action_collections.values():
                action_collection_list.add_Action_Collection(action_collection)
            self.collections.set_Action_Collections(action_collection_list)
        if len(self.object_collections) > 0:
            object_collection_list = bundle_binding.ObjectCollectionListType()
            for object_collection in self.object_collections.values():
                object_collection_list.add_Object_Collection(object_collection)
            self.collections.set_Object_Collections(object_collection_list)
        if len(self.behavior_collections) > 0:
            behavior_collection_list = bundle_binding.BehaviorCollectionListType()
            for behavior_collection in self.behavior_collections.values():
                behavior_collection_list.add_Behavior_Collection(behavior_collection)
            self.collections.set_Behavior_Collections(behavior_collection_list)
        if len(self.candidate_indicator_collections) > 0:
            candidate_indicator_collection_list = bundle_binding.CandidateIndicatorCollectionListType()
            for candidate_indicator_collection in self.candidate_indicator_collections.values():
                candidate_indicator_collection_list.add_Candidate_Indicator_Collection(candidate_indicator_collection)
            self.collections.set_Candidate_Indicator_Collections(candidate_indicator_collection_list)
        #Add the Collections
        if self.collections.hasContent_(): self.bundle.set_Collections(self.collections)

    #Build the namespace/schemalocation declaration string
    def __build_namespaces_schemalocations(self):
        output_string = '\n '
        schemalocs = []
        first_string = True
        for namespace_prefix, namespace in self.namespace_prefixes.items():
            output_string += (namespace_prefix + '=' + namespace + ' \n ')
        output_string += 'xsi:schemaLocation="'
        for namespace, schemalocation in self.schemalocations.items():
            if first_string:
                schemalocs.append(namespace + ' ' + schemalocation)
                first_string = False
            else:
                schemalocs.append(' ' + namespace + ' ' + schemalocation)
        for schemalocation_string in schemalocs:
            if schemalocs.index(schemalocation_string) == (len(schemalocs) - 1):
                output_string += (schemalocation_string + '"\n')
            else:
                output_string += (schemalocation_string + '\n')
        return output_string
