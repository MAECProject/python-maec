# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
# Methods for merging MAEC documents

import itertools
import maec
from copy import deepcopy
from cybox.core import Object
from cybox.common import HashList
from cybox.utils import Namespace
from maec.package import (Package, MalwareSubject, MalwareConfigurationDetails,
                          FindingsBundleList, MetaAnalysis, Analyses,
                          MinorVariants, MalwareSubjectRelationshipList,
                          MalwareSubjectList)

def dict_merge(target, *args):
    '''Merge multiple dictionaries into one'''
    if len(args) > 1:
        for obj in args:
            dict_merge(target, obj)
        return target
 
    # Recursively merge dicts and set non-dict values
    obj = args[0]
    if not isinstance(obj, dict):
        return obj
    for k, v in obj.iteritems():
        if k in target and isinstance(target[k], dict):
            dict_merge(target[k], v)
        elif k in target and isinstance(target[k], list):
                target[k] = (target[k] + v)
        else:
            target[k] = deepcopy(v)
    return target

def merge_documents(input_list, output_file):
    '''Merge a list of input MAEC documents and write them to an output file'''
    parsed_documents = []
    # Parse the documents and get their API representation
    for input_file in input_list:
        api_representation = maec.parse_xml_instance(input_file)['api']
        parsed_documents.append(api_representation)
    # Do a sanity check on the input list of documents
    for document in parsed_documents:
        if isinstance(document, Package):
            continue
        else:
            print 'Error: unsupported document type. Currently only MAEC Packages are supported'

    # Merge the MAEC packages
    merged_package = merge_packages(parsed_documents)
    # Write the merged package to the output file
    merged_package.to_xml_file(output_file, {"https://github.com/MAECProject/python-maec":"merged"})

def merge_packages(package_list, namespace = None):
    '''Merge a list of input MAEC Packages and return a merged Package instance.'''
    malware_subjects = []
    # Instantiate the ID generator class (for automatic ID generation)
    if not namespace:
        NS = Namespace("https://github.com/MAECProject/python-maec", "merged")
    else:
        NS = namespace
    maec.utils.set_id_namespace(NS)
    # Build the list of Malware Subjects
    for package in package_list:
        for malware_subject in package.malware_subjects:
            malware_subjects.append(malware_subject)
    # Merge the Malware Subjects
    merged_subjects = merge_malware_subjects(malware_subjects)
    # Merge the input namespace/schemaLocation dictionaries
    merged_namespaces = {}
    merged_schemalocations = {}
    for package in package_list:
        merged_namespaces.update(package.__input_namespaces__)
        merged_schemalocations.update(package.__input_schemalocations__)
    # Create a new Package with the merged Malware Subjects
    merged_package = Package()
    merged_package.malware_subjects = MalwareSubjectList(merged_subjects)
    merged_package.__input_namespaces__ = merged_namespaces
    merged_package.__input_schemalocations__ = merged_schemalocations
    return merged_package

def bin_malware_subjects(malware_subject_list, default_hash_type='md5'):
    '''Bin a list of Malware Subjects by hash
       Default = MD5
    '''
    binned_subjects = {}
    for malware_subject in malware_subject_list:
        mal_inst_obj = malware_subject.malware_instance_object_attributes
        if mal_inst_obj:
            obj_properties = mal_inst_obj.properties
            if obj_properties and obj_properties.hashes:
                for hash in obj_properties.hashes:
                    if hash.type_ and hash.simple_hash_value:
                        hash_type = ''
                        hash_value = ''
                        # Get the hash type
                        hash_type = str(hash.type_).lower()
                        # Get the hash value
                        hash_value = str(hash.simple_hash_value).lower()
                            
                        # Check the hash type and bin accordingly
                        if hash_type == default_hash_type:
                            if hash_value in binned_subjects:
                                binned_subjects[hash_value].append(malware_subject)
                            else:
                                binned_subjects[hash_value] = [malware_subject]
    return binned_subjects

def merge_entities(entity_list):
    '''Merge a list of MAEC/CybOX entities'''
    dict_list = [x.to_dict() for x in entity_list]
    output_dict = dict_merge({}, *dict_list)
    return output_dict

def deduplicate_vocabulary_list(entity_list, value_name = "value"): # TODO: Move this to the deduplicator module?
    '''Deduplicate a simple list of MAEC/CybOX vocabulary entries'''
    temp = []
    output_list = []
    for entity in entity_list:
        entity_value = getattr(entity, value_name)
        entity_lower = str(entity_value).lower()
        if entity_value and entity_lower not in temp:
            temp.append(entity_lower)
            output_list.append(entity)
        elif not entity_value:
            output_list.append(entity)
    return output_list

def merge_findings_bundles(findings_bundles_list):
    '''Merge two or more Malware Subject Findings Bundles'''
    # Merge the meta-analysis
    merged_meta_analysis = None
    meta_analysis_list = [x.meta_analysis for x in findings_bundles_list if x.meta_analysis]
    if meta_analysis_list:
        merged_meta_analysis = MetaAnalysis.from_dict(merge_entities(meta_analysis_list))
    # Merge the list of bundles
    merged_bundles = list(itertools.chain(*[x.bundle for x in findings_bundles_list if x.bundle]))
    # Merge the list of external bundle references
    merged_bundle_external_references = list(itertools.chain(*[x.bundle_external_reference for x in findings_bundles_list if x.bundle_external_reference]))

    # Construct the merged Findings Bundle List entity
    merged_findings_bundle_list = FindingsBundleList()
    if merged_meta_analysis:
        merged_findings_bundle_list.meta_analysis = merged_meta_analysis
    if merged_bundles:
        merged_findings_bundle_list.bundle = merged_bundles
    if merged_bundle_external_references:
        merged_findings_bundle_list.bundle_external_reference = merged_bundle_external_references

    return merged_findings_bundle_list

def create_mappings(mapping_dict, original_malware_subject_list, merged_malware_subject):
    '''Map the IDs of a list of existing Malware Subjects to the new merged Malware Subject'''
    for malware_subject in original_malware_subject_list:
        mapping_dict[malware_subject.id_] = merged_malware_subject.id_

def merge_binned_malware_subjects(merged_malware_subject, binned_list, id_mappings_dict):
    '''Merge a list of input binned (related) Malware Subjects'''
    # Merge the Malware_Instance_Object_Attributes
    mal_inst_obj_list = [x.malware_instance_object_attributes for x in binned_list]
    merged_inst_obj = Object.from_dict(merge_entities(mal_inst_obj_list))
    # Give the merged Object a new ID
    merged_inst_obj.id_ = maec.utils.idgen.create_id('object')
    # Deduplicate the hash values, if they exist
    if merged_inst_obj.properties and merged_inst_obj.properties.hashes:
        hashes = merged_inst_obj.properties.hashes
        hashes = HashList(deduplicate_vocabulary_list(hashes, value_name = 'simple_hash_value'))
        hashes = HashList(deduplicate_vocabulary_list(hashes, value_name = 'fuzzy_hash_value'))
        merged_inst_obj.properties.hashes = hashes
    # Merge and deduplicate the labels
    merged_labels = list(itertools.chain(*[x.label for x in binned_list if x.label]))
    deduplicated_labels = deduplicate_vocabulary_list(merged_labels)
    # Merge the configuration details
    config_details_list = [x.configuration_details for x in binned_list if x.configuration_details]
    merged_config_details = None
    if config_details_list:
        merged_config_details = MalwareConfigurationDetails.from_dict(merge_entities(config_details_list))
    # Merge the minor variants
    merged_minor_variants = list(itertools.chain(*[x.minor_variants for x in binned_list if x.minor_variants]))
    # Merge the field data # TODO: Add support. Not implemented in the APIs.
    # Merge the analyses
    merged_analyses = list(itertools.chain(*[x.analyses for x in binned_list if x.analyses]))
    # Merge the findings bundles
    merged_findings_bundles = merge_findings_bundles([x.findings_bundles for x in binned_list if x.findings_bundles])
    # Merge the relationships
    merged_relationships = list(itertools.chain(*[x.relationships for x in binned_list if x.relationships]))
    # Merge the compatible platforms
    merged_compatible_platforms = list(itertools.chain(*[x.compatible_platform for x in binned_list if x.compatible_platform]))



    # Build the merged Malware Subject
    merged_malware_subject.malware_instance_object_attributes = merged_inst_obj
    if deduplicated_labels: merged_malware_subject.label = deduplicated_labels
    if merged_config_details: merged_malware_subject.configuration_details = merged_config_details
    if merged_minor_variants: merged_malware_subject.minor_variants = MinorVariants(merged_minor_variants)
    if merged_analyses: merged_malware_subject.analyses = Analyses(merged_analyses)
    if merged_findings_bundles: merged_malware_subject.findings_bundles = merged_findings_bundles
    if merged_relationships: merged_malware_subject.relationships = MalwareSubjectRelationshipList(merged_relationships)
    if merged_compatible_platforms: merged_malware_subject.compatible_platform = merged_compatible_platforms

def update_relationships(malware_subject_list, id_mappings):
    '''Update any existing Malware Subject relationships to account for merged Malware Subjects'''
    for malware_subject in malware_subject_list:
        if malware_subject.relationships:
            relationships = malware_subject.relationships 
            for relationship in relationships:
                malware_subject_references = relationship.malware_subject_references
                for malware_subject_reference in malware_subject_references:
                    if malware_subject_reference.malware_subject_idref in id_mappings.keys():
                        malware_subject_reference.malware_subject_idref = id_mappings[malware_subject_reference.malware_subject_idref]

def merge_malware_subjects(malware_subject_list):
    '''Merge a list of input Malware Subjects'''
    id_mappings = {}
    output_subjects = []
    # Bin the Malware Subjects by hash
    binned_subjects = bin_malware_subjects(malware_subject_list)
    # Merge the Malware Subjects that were binned
    for binned_list in binned_subjects.values():
        # Make sure we're dealing with at least two subjects
        if len(binned_list) > 1:
            # Instantiate the merged Malware Subject
            merged_malware_subject = MalwareSubject()
            # Add the ID mappings from the old (merged) subject to the new one
            create_mappings(id_mappings, binned_list, merged_malware_subject)
            # Perform the merging
            merge_binned_malware_subjects(merged_malware_subject, binned_list, id_mappings)
            # Add the merged Malware Subject to the output list
            output_subjects.append(merged_malware_subject)
    # Add the Malware Subjects that weren't merged
    for malware_subject in malware_subject_list:
        if malware_subject.id_ not in id_mappings.keys():
            output_subjects.append(malware_subject)
    # Update the relationships for the Malware Subjects to account for the merges
    update_relationships(output_subjects, id_mappings)
    # Return the list of original and merged Malware Subjects
    return output_subjects