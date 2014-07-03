# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.
# Methods for merging MAEC documents

import sys
import itertools
import maec
from copy import deepcopy
from cybox.core import Object
from maec.package.package import Package
from maec.bundle.bundle import Bundle
from maec.package.malware_subject import MalwareSubject, MalwareConfigurationDetails,\
                                         FindingsBundleList, MetaAnalysis, Analyses,\
                                         MinorVariants, MalwareSubjectRelationshipList

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
    merge_packages(parsed_documents, output_file)

def merge_packages(package_list, output_file):
    '''Merge a list of input MAEC Packages and write them to an output Package file'''
    malware_subjects = []
    # Build the list of Malware Subjects
    for package in package_list:
        for malware_subject in package.malware_subjects:
            malware_subjects.append(malware_subject)
    # Merge the Malware Subjects
    merged_subjects = merge_malware_subjects(malware_subjects)
    # Create a new Package with the merged Malware Subjects

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
                hashes_list = obj_properties.hashes.to_list()
                for hash_dict in hashes_list:
                    if 'type' in hash_dict and 'simple_hash_value' in hash_dict:
                        hash_type = ''
                        hash_value = ''
                        # Get the hash type
                        if isinstance(hash_dict['type'], str):
                            hash_type = str(hash_dict['type']).lower()
                        elif isinstance(hash_dict['type'], dict):
                            hash_type = str(hash_dict['type']['value']).lower()
                        # Get the hash value
                        if isinstance(hash_dict['simple_hash_value'], str):
                            hash_value = str(hash_dict['simple_hash_value']).lower()
                        elif isinstance(hash_dict['simple_hash_value'], dict):
                            hash_value = str(hash_dict['simple_hash_value']['value']).lower()
                            
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

def deduplicate_vocabulary_list(entity_list): # TODO: Move this to the deduplicator module?
    '''Deduplicate a simple list of MAEC/CybOX vocabulary entries'''
    temp = []
    output_list = []
    for entity in entity_list:
        if entity.value and entity.value not in temp:
            temp.append(entity.value)
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
    merged_bundles = list(itertools.chain(*[x.bundles for x in findings_bundles_list if x.bundles]))
    # Merge the list of external bundle references
    merged_bundle_external_references = list(itertools.chain(*[x.bundle_external_references for x in findings_bundles_list if x.bundle_external_references]))

    # Construct the merged Findings Bundle List entity
    merged_findings_bundle_list = FindingsBundleList()
    if merged_meta_analysis:
        merged_findings_bundle_list.meta_analysis = merged_meta_analysis
    if merged_bundles:
        merged_findings_bundle_list.bundles = merged_bundles
    if merged_bundle_external_references:
        merged_findings_bundle_list.bundle_external_references = merged_bundle_external_references

    return merged_findings_bundle_list

def merge_malware_subjects(malware_subject_list):
    '''Merge a list of input Malware Subjects'''
    output_subjects = []
    # Bin the Malware Subjects by hash
    binned_subjects = bin_malware_subjects(malware_subject_list)
    # Merge the Malware Subjects that were binned
    for binned_list in binned_subjects.values():
        # Make sure we're dealing with at least two subjects
        if len(binned_list) > 1:
            # Merge the Malware_Instance_Object_Attributes # TODO: Determine what to do with the ID?
            # TODO: Deduplicate hashes?
            mal_inst_obj_list = [x.malware_instance_object_attributes for x in binned_list]
            print merge_entities(mal_inst_obj_list)
            merged_inst_obj = Object.from_dict(merge_entities(mal_inst_obj_list))
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
            # Merge the relationships # TODO: Determine what to do about the Malware Subject IDs
            merged_relationships = list(itertools.chain(*[x.relationships for x in binned_list if x.relationships]))
            # Merge the compatible platforms
            merged_compatible_platforms = list(itertools.chain(*[x.compatible_platform for x in binned_list if x.compatible_platform]))

            # Build the merged Malware Subject
            merged_malware_subject = MalwareSubject()
            merged_malware_subject.malware_instance_object_attributes = merged_inst_obj
            if deduplicated_labels: merged_malware_subject.label = deduplicated_labels
            if merged_config_details: merged_malware_subject.configuration_details = merged_config_details
            if merged_minor_variants: merged_malware_subject.minor_variants = MinorVariants(merged_minor_variants)
            if merged_analyses: merged_malware_subject.analyses = Analyses(merged_analyses)
            if merged_findings_bundles: merged_malware_subject.findings_bundles = merged_findings_bundles
            if merged_relationships: merged_malware_subject.relationships = MalwareSubjectRelationshipList(merged_relationships)
            if merged_compatible_platforms: merged_malware_subject.compatible_platform = merged_compatible_platforms
