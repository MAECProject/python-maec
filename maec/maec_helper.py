#MAEC Helper Classes - a rough cut at a MAEC API

#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 12/14/2012

import maec_bundle_3_0 as maecbundle
import maec_package_1_0 as maecpackage
import datetime

import cybox_helper.objects.address_object as maec_address_object
import cybox_helper.objects.file_object as maec_file_object
import cybox_helper.objects.internet_object as maec_internet_object
import cybox_helper.objects.library_object as maec_library_object
import cybox_helper.objects.memory_object as maec_memory_object
import cybox_helper.objects.mailslot_object as maec_mailslot_object
import cybox_helper.objects.mutex_object as maec_mutex_object
import cybox_helper.objects.pipe_object as maec_pipe_object
import cybox_helper.objects.port_object as maec_port_object
import cybox_helper.objects.process_object as maec_process_object
import cybox_helper.objects.registry_object as maec_registry_object
import cybox_helper.objects.socket_object as maec_socket_object
import cybox_helper.objects.uri_object as maec_uri_object
import cybox_helper.objects.win_driver_object as maec_win_driver_object
import cybox_helper.objects.win_executable_file_object as maec_win_executable_file_object
import cybox_helper.objects.win_file_object as maec_win_file_object
import cybox_helper.objects.win_process_object as maec_win_process_object
import cybox_helper.objects.win_kernel_hook_object as maec_win_kernel_hook_object
import cybox_helper.objects.win_service_object as maec_win_service_object
import cybox_helper.objects.win_handle_object as maec_win_handle_object
import cybox_helper.objects.win_task_object as maec_win_task_object
import cybox_helper.objects.win_user_object as maec_win_user_object
import cybox_helper.objects.win_network_share_object as maec_win_newtwork_share_object
import cybox_helper.objects.win_system_object as maec_win_system_object
import cybox_helper.objects.win_thread_object as maec_win_thread_object
        
class generator:
    def __init__(self, namespace):
        self.namespace = namespace
        self.general_id_base = 0
        self.pkg_id_base = 0
        self.sub_id_base = 0
        self.bnd_id_base = 0
        self.act_id_base = 0
        self.bhv_id_base = 0
        self.obj_id_base = 0
        self.ana_id_base = 0
        self.tol_id_base = 0
        self.eff_id_base = 0
        self.api_id_base = 0
        self.cde_id_base = 0
        self.imp_id_base = 0
        self.dat_id_base = 0
        self.actc_id_base = 0
        self.bhvc_id_base = 0
        self.objc_id_base = 0
        self.indc_id_base = 0
        self.avclass_id_base = 0
        
    #Methods for generating unique ids
    def generate_id(self):
        self.general_id_base += 1
        return self.general_id_base

    def generate_pkg_id(self):
        self.pkg_id_base += 1
        return 'maec-' + self.namespace + '-pkg-' + str(self.pkg_id_base)

    def generate_sub_id(self):
        self.sub_id_base += 1
        return 'maec-' + self.namespace + '-sub-' + str(self.sub_id_base)
    
    def generate_bnd_id(self):
        self.bnd_id_base += 1
        return 'maec-' + self.namespace + '-bnd-' + str(self.bnd_id_base)
    
    def generate_act_id(self):
        self.act_id_base += 1
        return 'maec-' + self.namespace + '-act-' + str(self.act_id_base)
    
    def generate_bhv_id(self):
        self.bhv_id_base += 1
        return 'maec-' + self.namespace + '-bhv-' + str(self.bhv_id_base)
    
    def generate_obj_id(self):
        self.obj_id_base += 1
        return 'maec-' + self.namespace + '-obj-' + str(self.obj_id_base)
    
    def generate_ana_id(self):
        self.ana_id_base += 1
        return 'maec-' + self.namespace + '-ana-' + str(self.ana_id_base)
    
    def generate_tol_id(self):
        self.tol_id_base += 1
        return 'maec-' + self.namespace + '-tol-' + str(self.tol_id_base)
        
    def generate_eff_id(self):
        self.eff_id_base += 1
        return 'maec-' + self.namespace + '-eff-' + str(self.eff_id_base)
        
    def generate_api_id(self):
        self.api_id_base += 1
        return 'maec-' + self.namespace + '-api-' + str(self.api_id_base)
        
    def generate_cde_id(self):
        self.cde_id_base += 1
        return 'maec-' + self.namespace + '-cde-' + str(self.cde_id_base)
        
    def generate_imp_id(self):
        self.imp_id_base += 1
        return 'maec-' + self.namespace + '-imp-' + str(self.imp_id_base)
        
    def generate_dat_id(self):
        self.dat_id_base += 1
        return 'maec-' + self.namespace + '-dat-' + str(self.dat_id_base)
        
    def generate_actc_id(self):
        self.actc_id_base += 1
        return 'maec-' + self.namespace + '-actc-' + str(self.actc_id_base)

    def generate_bhvc_id(self):
        self.bhvc_id_base += 1
        return 'maec-' + self.namespace + '-bhvc-' + str(self.bhvc_id_base)

    def generate_objc_id(self):
        self.objc_id_base += 1
        return 'maec-' + self.namespace + '-objc-' + str(self.objc_id_base)

    def generate_indc_id(self):
        self.indc_id_base += 1
        return 'maec-' + self.namespace + '-indc-' + str(self.indc_id_base)

    def generate_avclass_id(self):
        self.avclass_id_base += 1
        return 'mmdef-class-' + str(self.avclass_id_base)
    
    #Methods for getting current id bases
    def get_current_obj_id(self):
        return self.obj_id_base

class maec_package:
    def __init__(self, generator, schema_version):
        self.generator = generator
        #Create the MAEC Package object
        self.package = maecpackage.PackageType(id=self.generator.generate_pkg_id())
        #Set the schema version
        self.package.set_schema_version(schema_version)
        #Create the subject list
        self.subjects = maecpackage.MalwareSubjectListType()
        #Create the namespace and schemalocation declarations
        self.namespace_prefixes = {'xmlns:maecPackage' : '"http://maec.mitre.org/XMLSchema/maec-package-1"',
                                   'xmlns:maecBundle' : '"http://maec.mitre.org/XMLSchema/maec-bundle-3"',
                                   'xmlns:cybox' : '"http://cybox.mitre.org/cybox_v1"',
                                   'xmlns:Common' : '"http://cybox.mitre.org/Common_v1"',
                                   'xmlns:mmdef' : '"http://xml/metadataSharing.xsd"',
                                   'xmlns:xsi' : '"http://www.w3.org/2001/XMLSchema-instance"'}
        self.schemalocations = {'http://maec.mitre.org/XMLSchema/maec-package-1' : 'http://maec.mitre.org/language/version3.0/maec-package-schema.xsd',
                                'http://maec.mitre.org/XMLSchema/maec-bundle-3' :  'http://maec.mitre.org/language/version3.0/maec-bundle-schema.xsd',
                                'http://cybox.mitre.org/Common_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_common_types_v1.0.xsd',
                                'http://cybox.mitre.org/cybox_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_core_v1.0.xsd',
                                'http://xml/metadataSharing.xsd' : 'http://grouper.ieee.org/groups/malware/malwg/Schema1.2/metadataSharing.xsd'}

    #Public methods

    #Add a malware subject
    def add_malware_subject(self, malware_subject):
        self.subjects.add_Malware_Subject(malware_subject)
    
    #Set the grouping relationship based on an input dictionary
    def set_grouping_relationship(self, grouping_relationship_attributes):
        for key, value in grouping_relationship_attributes.items():
            pass

    #Add a namespace to the namespaces list
    def add_namespace(self, namespace_prefix, namespace):
        self.namespace_prefixes[namespace_prefix] = '"' + namespace + '"'

    #Add a schemalocation to the schemalocation list
    def add_schemalocation(self, namespace, schemalocation):
        self.schemalocations[namespace] = schemalocation

    #Get the package
    def get_object(self):
        self.__build__()
        return self.package

    #Export the package and its contents to an XML file
    def export_to_file(self, outfilename):
        self.__build__()
        outfile = open(outfilename, 'w')
        self.package.export(outfile, 0, namespacedef_=self.__build_namespaces_schemalocations())


    #Private methods

    #Build the package, adding any list or other items
    def __build__(self):
        if self.subjects.hasContent_():
            self.package.set_Malware_Subjects(self.subjects)

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

class maec_subject:
    def __init__(self, generator, schema_version, malware_instance_object = None):
        self.generator = generator
        #Create the MAEC Subject object
        self.subject = maecpackage.MalwareSubjectType(id=self.generator.generate_sub_id())
        #Set the Malware Instance Object Attributes (a CybOX object) if they are not none
        if malware_instance_object is not None:
            self.subject.set_Malware_Instance_Object_Attributes(malware_instance_object)
        #Instantiate the lists
        self.analyses = maecpackage.AnalysisListType()
        self.findings_bundles = maecpackage.FindingsBundleListType()

    #Public methods
    #Set the Malware_Instance_Object_Attributes with a CybOX object
    def set_malware_instance_object_attributes(self, malware_instance_object):
        self.subject.set_Malware_Instance_Object_Attributes(malware_instance_object)

    #Add an Analysis to the Analyses
    def add_analysis(self, analysis):
        self.analyses.add_Analysis(analysis)

    #Add a MAEC Bundle to the Findings Bundles
    def add_findings_bundle(self, findings_bundle):
        self.findings_bundles.add_Bundle(findings_bundle)

    #Get the Malware Subject
    def get_object(self):
        self.__build__()
        return self.subject
    
    #Private methods

    #Build the Subject, adding any list or other items
    def __build__(self):
        if self.analyses.hasContent_():
            self.subject.set_Analyses(self.analyses)
        if self.findings_bundles.hasContent_():
            self.subject.set_Findings_Bundles(self.findings_bundles)

class maec_bundle:
    def __init__(self, generator, schema_version, defined_subject, content_type = None, malware_instance_object = None):
        self.generator = generator
        #Create the MAEC Bundle object
        self.bundle = maecbundle.BundleType(id=self.generator.generate_bnd_id())
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
        #Add all of the top-level containers
        self.actions = maecbundle.ActionListType()
        self.process_tree = maecbundle.ProcessTreeType()
        self.behaviors = maecbundle.BehaviorListType()
        self.objects = maecbundle.ObjectListType()
        self.candidate_indicators = maecbundle.CandidateIndicatorListType()
        self.collections = maecbundle.CollectionsType()
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
                action_collection = maecbundle.ActionCollectionType(id=self.generator.generate_actc_id(), name = action_collection_name)
                action_list = maecbundle.ActionListType()
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
                object_collection = maecbundle.ObjectCollectionType(id=self.generator.generate_objc_id(), name = object_collection_name)
                object_list = maecbundle.ObjectListType()
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
                behavior_collection = maecbundle.BehaviorCollectionType(id=self.generator.generate_bhvc_id(), name = behavior_collection_name)
                behavior_list = maecbundle.BehaviorListType()
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
                candidate_indicator_collection = maecbundle.CandidateIndicatorCollectionType(id=self.generator.generate_indc_id(), name = candidate_indicator_collection_name)
                candidate_indicator_list = maecbundle.CandidateIndicatorListType()
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
        
    #Accessor methods
    def get_object(self):
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
            action_collection_list = maecbundle.ActionCollectionListType()
            for action_collection in self.action_collections.values():
                action_collection_list.add_Action_Collection(action_collection)
            self.collections.set_Action_Collections(action_collection_list)
        if len(self.object_collections) > 0:
            object_collection_list = maecbundle.ObjectCollectionListType()
            for object_collection in self.object_collections.values():
                object_collection_list.add_Object_Collection(object_collection)
            self.collections.set_Object_Collections(object_collection_list)
        if len(self.behavior_collections) > 0:
            behavior_collection_list = maecbundle.BehaviorCollectionListType()
            for behavior_collection in self.behavior_collections.values():
                behavior_collection_list.add_Behavior_Collection(behavior_collection)
            self.collections.set_Behavior_Collections(behavior_collection_list)
        if len(self.candidate_indicator_collections) > 0:
            candidate_indicator_collection_list = maecbundle.CandidateIndicatorCollectionListType()
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

class maec_analysis:
    def __init__(self, generator, method = None, type = None):
        self.generator = generator
        self.analysis = maecpackage.AnalysisType(id=self.generator.generate_ana_id())
        if method is not None:
            self.analysis.set_method(method)
        if type is not None:
            self.analysis.set_type(type)
        self.tool_list = maecpackage.ToolListType()

    #"Public" methods
    def set_findings_bundle_reference(self, bundle_idref):
        bundle_reference = maecbundle.BundleReferenceType(bundle_idref = bundle_idref)
        self.analysis.set_Findings_Bundle_Reference(bundle_reference)

    def set_summary(self, summary):
        self.analysis.set_Summary(summary)
   
    def add_tool(self, tool_dictionary):
        self.__create_tool(tool_dictionary)

    def get_object(self):
        if self.tool_list.hasContent_():
            self.analysis.set_Tools(self.tool_list)
        return self.analysis
    
    #"Private" methods

    #Create the MAEC tool type
    def __create_tool(self, tool_dictionary):
        #Create the Tool and set its ID
        tool = maecpackage.cybox_common_types_1_0.ToolInformationType(id=self.generator.generate_tol_id())
        for key, value in tool_dictionary.items():
            if key.lower() == 'description':
                if value is not None and len(value) > 0:
                    tool.set_Description(value)
            elif key.lower() == 'vendor':
                if value is not None and len(value) > 0:
                    tool.set_Vendor(value)
            elif key.lower() == 'name':
                if value is not None and len(value) > 0:
                    tool.set_Name(value)  
            elif key.lower() == 'version':
                if value is not None and len(value) > 0:
                    tool.set_Version(value)
        if tool.hasContent_():
            self.tool_list.add_Tool(tool)
    
    def __build__(self):
        if self.tool_list.hasContent_():
            self.analysis.set_Tools(tool_list)      

class maec_action:
    def __init__(self, generator, action_attributes):
        self.generator = generator
        #Create the action type and add basic attributes
        self.action = maecbundle.MalwareActionType()
        self.action.set_id(self.generator.generate_act_id())
        self.associated_objects = maecbundle.cybox_core_1_0.AssociatedObjectsType()
        for key, value in action_attributes.items():
            if key == 'undefined_name':
                self.action.set_undefined_name(value)
            elif key == 'name':
                self.action.set_name(value)
            elif key == 'action_status':
                self.action.set_action_status(value)
            elif key == 'action_type':
                if value.count('/') > 0:
                    self.action.set_type(value)
                else:
                    self.action.set_type(value.capitalize())
            elif key == 'object':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'secondary_object':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'object_old':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'object_new':
                if value is not None and value.hasContent_():
                    self.associated_objects.add_Associated_Object(value)
            elif key == 'context':
                self.action.set_context(value)
            elif key == 'network_protocol':
                self.action.set_network_protocol(value)
            #elif key == 'tool_id':
            #    discovery_method = maec.common.MeasureSourceType()
            #    tools = maec.common.ToolsInformationType()
            #    tool=maec.common.ToolInformationType(idref=value)
            #    tools.add_Tool(tool)
            #    discovery_method.set_Tools(tools)
            #    action.set_Discovery_Method(discovery_method)
            elif key == 'action_arguments':
                action_arguments = maecbundle.cybox_core_1_0.ActionArgumentsType()
                for argument in value:
                    action_argument = maecbundle.cybox_core_1_0.ActionArgumentType()
                    for key, value in argument.items():
                        if key == 'defined_argument_name':
                            action_argument.set_defined_argument_name(value)
                        elif key == 'undefined_argument_name':
                            action_argument.set_undefined_argument_name(value)
                        elif key == 'argument_value':
                            action_argument.set_argument_value(value)
                    action_arguments.add_Action_Argument(action_argument)
                if action_arguments.hasContent_():
                    self.action.set_Action_Arguments(action_arguments)

        if associated_objects.hasContent_():
            self.action.set_Associated_Objects(associated_objects)
    
    #Getter methods
    def get_object(self):
        return self.action
            
class maec_object:
    def __init__(self, generator):
        self.generator = generator
            
    def create_socket_object(self, socket_attributes):
        cybox_object = maecbundle.cybox_core_1_0.AssociatedObjectType(id=self.generator.generate_obj_id(), type_='Socket')
        socketobj = socket_object.SocketObjectType()
        socketobj.set_anyAttributes_({'xsi:type' : 'SocketObj:SocketObjectType'})
        remote_address = socket_object.SocketAddressType()
        local_address = socket_object.SocketAddressType()
        
        for key, value in socket_attributes.items():
            if key == 'address_family' and self.__value_test(value):
                if value == "unspecified":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_UNSPEC'))
                elif value == "berkeley" or value == "ipv4":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_INET'))
                elif value == "ipv6":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_INET6'))
                elif value == "ipx":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_IPX'))
                elif value == "netbios":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_NETBIOS'))
                elif value == "appletalk":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_APPLETALK'))
                elif value == "irda":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_IRDA'))
                elif value == "bth":
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='AF_BTH'))
                elif "af_" in value:
                    socketobj.set_Address_Family(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == "domain" and self.__value_test(value):
                if value == "local":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_LOCAL'))
                elif value == "unix":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_UNIX'))
                elif value == "inet" or value == "ipv4" or value == "ip":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_INET'))
                elif value == "file":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_FILE'))
                elif value == "ax.25":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_AX25'))
                elif value == "ipx":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_IPX'))
                elif value == "ipv6":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_INET6'))
                elif value == "appletalk":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_APPLETALK'))
                elif value == "netrom":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_NETROM'))
                elif value == "bridge":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_BRIDGE'))
                elif value == "atmpvc":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_ATMPVC'))
                elif value == "x.25":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_X25'))
                elif value == "rose":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_ROSE'))
                elif value == "key":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_KEY'))
                elif value == "security":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_SECURITY'))
                elif value == "netbeui":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_NETBEUI'))
                elif value == "netlink":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_NETLINK'))
                elif value == "route":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_ROUTE'))
                elif value == "decnet":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_DECNET'))
                elif value == "packet":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_PACKET'))
                elif value == "ash":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_ASH'))
                elif value == "econet":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_ECONET'))
                elif value == "atmsvc":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_ATMSVC'))
                elif value == "sna":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_SNA'))
                elif value == "irda":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_IRDA'))
                elif value == "pppox":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_PPPOX'))
                elif value == "wanpipe":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_WANPIPE'))
                elif value == "bluetooth":
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='PF_BLUETOOTH'))
                elif 'PF_' in value:
                    socketobj.set_Domain(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == 'options':
                options = socket_object.SocketOptionsType()
                for op_key, op_value in value.items():
                    # TODO: populate options
                    pass
                socketobj.set_Options(options)
            elif key == 'protocol' and self.__value_test(value):
                if value == 'icmp':
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='IPPROTO_ICMP'))
                elif value == 'icmpv6':
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='IPPROTO_ICMPV6'))
                elif value == 'igmp':
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='IPPROTO_IGMP'))
                elif value == 'udp':
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='IPPROTO_TCP'))
                elif value == 'tcp':
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='IPPROTO_UDP'))
                elif value == 'rm':
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='IPPROTO_ICMP'))
                elif value == 'bluetooth':
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='BTHPROTO_RFCOMM'))
                elif 'PROTO_' in value:
                    socketobj.set_Protocol(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == 'type' and self.__value_test(value):
                if value == 'tcp':
                    socketobj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='SOCK_STREAM'))
                elif value == 'udp':
                    socketobj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='SOCK_DGRAM'))
                elif value == 'raw':
                    socketobj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='SOCK_RAW'))
                elif value == 'rdm':
                    socketobj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='SOCK_RDM'))
                elif value == 'congestion control':
                    socketobj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_='SOCK_SEQPACKET'))
                elif 'SOCK_' in value:
                    socketobj.set_Type(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == 'remote_port' and self.__value_test(value):
                if value != '0':
                    port = socket_object.port_object_1_3.PortObjectType()
                    port.set_Port_Value(maecbundle.cybox_common_types_1_0.PositiveIntegerObjectAttributeType(datatype='PositiveInteger', valueOf_=maec.quote_xml(value)))
                    remote_address.set_Port(port)
            elif key == 'remote_address' and self.__value_test(value):
                ip_address = socket_object.address_object_1_2.AddressObjectType(category='ipv4-addr')
                ip_address.set_Address_Value(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maec.quote_xml(value)))
                remote_address.set_IP_Address(ip_address)
            elif key == 'local_port' and self.__value_test(value):
                if value != '0':
                    port = socket_object.port_object_1_3.PortObjectType()
                    port.set_Port_Value(maecbundle.cybox_common_types_1_0.PositiveIntegerObjectAttributeType(datatype='PositiveInteger', valueOf_=maec.quote_xml(value)))
                    local_address.set_Port(port)
            elif key == 'local_address' and self.__value_test(value):
                ip_address = socket_object.address_object_1_2.AddressObjectType(category='ipv4-addr')
                ip_address.set_Address_Value(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=maec.quote_xml(value)))
                local_address.set_IP_Address(ip_address)
            elif key == 'is_listening' and self.__value_test(value):
                socketobj.set_is_listening(value)
            elif key == 'is_blocking' and self.__value_test(value):
                socketobj.set_is_blocking(value)
            elif key == 'association' and self.__value_test(value):
                cybox_object.set_association_type(value)
        if remote_address.hasContent_():
            socketobj.set_Remote_Address(remote_address)
        if local_address.hasContent_():
            socketobj.set_Local_Address(local_address)
            
        if socketobj.hasContent_():
            cybox_object.set_Defined_Object(socketobj)
        
        return cybox_object

    def create_port_object(self, port_attributes):
        port = maec_port_object.port_object(self.generator.generate_obj_id())
        return port.build_object(port_attributes)
            
    def create_library_object(self, library_attributes):
        library = maec_library_object.library_object(self.generator.generate_obj_id())
        return library.build_object(library_attributes)

    def create_win_kernel_hook_object(self, win_kernel_hook_attributes):
        win_kernel_hook = maec_win_kernel_hook_object.win_kernel_hook_object(self.generator.generate_obj_id())
        return win_kernel_hook.build_object(win_kernel_hook_attributes)

    def create_address_object(self, address_attributes):
        address = maec_address_object.address_object(self.generator.generate_obj_id())
        return address.build_object(address_attributes)

    def create_uri_object(self, uri_attributes):
        uri = maec_uri_object.uri_object(self.generator.generate_obj_id())
        return uri.build_object(uri_attributes)

    def create_registry_object(self, registry_attributes):
        registry = maec_registry_object.registry_object(self.generator.generate_obj_id())
        return registry.build_object(registry_attributes)

    def create_file_object(self, file_attributes):
        file = maec_file_object.file_object(self.generator.generate_obj_id())
        return file.build_object(file_attributes)

    def create_win_file_object(self, win_file_attributes):
        win_file = maec_win_file_object.win_file_object(self.generator.generate_obj_id())
        return win_file.build_object(win_file_attributes)
    
    def create_pipe_object(self, pipe_attributes):
        pipe = maec_pipe_object.pipe_object(self.generator.generate_obj_id())
        return pipe.build_object(pipe_attributes)
    
    def create_process_object(self, process_attributes):
        process = maec_process_object.process_object(self.generator.generate_obj_id())
        return process.build_object(process_attributes)
        
    def create_win_process_object(self, win_process_attributes):
        win_process = maec_win_process_object.win_process_object(self.generator.generate_obj_id())
        return win_process.build_object(win_process_attributes)

    def create_memory_object(self, memory_attributes):
        memory = maec_memory_object.memory_object(self.generator.generate_obj_id())
        return memory.build_object(memory_attributes)
            
    def create_internet_object(self, internet_attributes):
        internet = maec_internet_object.internet_object(self.generator.generate_obj_id())
        return internet.build_object(internet_attributes)
    
    def create_win_service_object(self, service_attributes):
        service = maec_win_service_object.win_service_object(self.generator.generate_obj_id())
        return service.build_object(service_attributes)

    def create_mutex_object(self, mutex_attributes):
        mutex = maec_mutex_object.mutex_object(self.generator.generate_obj_id())
        return mutex.build_object(mutex_attributes)
    
    def create_win_driver_object(self, driver_attributes):
        win_driver = maec_win_driver_object.win_driver_object(self.generator.generate_obj_id())
        return win_driver.build_object(driver_attributes)
    
    def create_mailslot_object(self, mailslot_attributes):
        win_mailslot = maec_mailslot_object.win_mailslot_object(self.generator.generate_obj_id())
        return win_mailslot.build_object(mailslot_attributes)

    def create_win_executable_file_object(self, win_executable_file_attributes):
        win_executable_file = maec_win_executable_file_object.win_executable_file_object(self.generator.generate_obj_id())
        return win_executable_file.build_object(win_executable_file_attributes)

    def create_win_handle_object(self, handle_attributes):
        win_handle = maec_win_handle_object.win_handle_object(self.generator.generate_obj_id())
        return win_handle.build_object(handle_attributes)

    def create_win_thread_object(self, thread_attributes):
        win_thread = maec_win_thread_object.win_thread_object(self.generator.generate_obj_id())
        return win_thread.build_object(thread_attributes)

    def create_win_task_object(self, task_attributes):
        win_task = maec_win_task_object.win_task_object(self.generator.generate_obj_id())
        return win_task.build_object(task_attributes)

    def create_win_user_object(self, user_attributes):
        win_user = maec_win_user_object.win_user_object(self.generator.generate_obj_id())
        return win_user.build_object(user_attributes)

    def create_win_network_share_object(self, share_attributes):
        win_newtwork_share = maec_win_newtwork_share_object.win_network_share_object(self.generator.generate_obj_id())
        return win_newtwork_share.build_object(share_attributes)

    def create_win_system_object(self, system_attributes):
        win_system = maec_win_system_object.win_system_object(self.generator.generate_obj_id())
        return win_system.build_object(system_attributes)
    
    #Create a related object based on a cybox object and relationhip
    def create_related_object(self, cybox_object, relationship):
        defined_object = cybox_object.get_Defined_Object()
        related_object = maecbundle.cybox_core_1_0.RelatedObjectType(id=self.generator.generate_obj_id(), type_=cybox_object.get_type(), Defined_Object = defined_object, relationship = relationship)
        return related_object

    def create_av_classifications(self, classifications):
        av_classifications = maecbundle.AVClassificationsType(type_='maec:AVClassificationsType')
        for classification in classifications:
            av_classification = maecbundle.mmdef_1_2.classificationObject(type_='dirty', id=self.generator.generate_avclass_id())
            classificationdetails = maecbundle.mmdef_1_2.classificationDetails()
            for key, value in classification.items():
                if key == 'company' and self.__value_test(value):
                    av_classification.set_companyName(value)
                elif key == 'application_version' and self.__value_test(value):
                    classificationdetails.set_productVersion(value)
                elif key == 'signature_version' and self.__value_test(value):
                    classificationdetails.set_definitionVersion(value)
                elif key == 'classification' and self.__value_test(value):
                    av_classification.set_classificationName(value)
            if classificationdetails.hasContent_():
                av_classification.set_classificationDetails(classificationdetails)
            if av_classification.hasContent_():
                av_classifications.add_AV_Classification(av_classification)
        return av_classifications

    #Create a state change effect for an action
    def __create_state_change_effect(self, new_defined_object):
        state_change_effect = maecbundle.cybox_core_1_0.StateChangeEffectType(effect_type = 'State_Changed')
        new_state = maecbundle.cybox_core_1_0.StateType(Defined_Object = new_defined_object)
        state_change_effect.set_New_State(new_state)
        return state_change_effect

    #Create a data read/write effect for an action
    def __create_data_effect(self, effect_attributes, type):
        data_effect = None
        if 'read' in type.lower():
            data_effect = maecbundle.cybox_core_1_0.DataReadEffectType(effect_type='Data_Read')
            data_effect.set_extensiontype_('cybox:DataReadEffectType')
        elif 'write' in type.lower():
            data_effect = maecbundle.cybox_core_1_0.DataWrittenEffectType(effect_type='Data_Written')
            data_effect.set_extensiontype_('cybox:DataWrittenEffectType')
        data_segment = maecbundle.cybox_common_types_1_0.DataSegmentType()
        for key, value in effect_attributes.items():
            if key == 'data_format' and self.__value_test(value):
                data_segment.set_Data_Format(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == 'data_size' and self.__value_test(value):
                data_segment.set_Data_Size(maecbundle.cybox_common_types_1_0.DataSizeType(units='Bytes', datatype='String', valueOf_=value))
            elif key == 'data_segment' and self.__value_test(value):
                data_segment.set_Data_Segment(maecbundle.cybox_common_types_1_0.StringObjectAttributeType(datatype='String', valueOf_=value))
            elif key == 'offset' and self.__value_test(value):
                data_segment.set_Offset(maecbundle.cybox_common_types_1_0.IntegerObjectAttributeType(datatype='Int', valueOf_=value))
        if data_segment.hasContent_():
            data_effect.set_Data(data_segment)
        return data_effect
    
    #Test if a value is not None and has a length greater than 0
    def __value_test(self, value):
        if value is not None and len(str(value)) > 0:
            return True
        else:
            return False
