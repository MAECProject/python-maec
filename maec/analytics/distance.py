# MAEC Distance Measure-related Classes - BETA
# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

# See LICENSE.txt for complete terms
import sys
try:
    import numpy
except ImportError:
    sys.stdout.write("Error: unable to import required numpy module.\nSee https://pypi.python.org/pypi/numpy.")
import os
import subprocess
import maec
import itertools
import math
from maec.package.package import Package
from maec.package.malware_subject import MalwareSubject
from maec.utils.deduplicator import BundleDeduplicator
from maec.utils.merge import merge_malware_subjects
from maec.analytics.static_features import static_features_dict

class DynamicFeatureVector(object):
    '''Generate a feature vector for a Malware Subject based on its dynamic features'''
    def __init__(self, malware_subject, deduplicator, ignored_object_properties, ignored_actions):
        self.deduplicator = deduplicator
        self.dynamic_features = []
        self.unique_dynamic_features = []
        self.ignored_object_properties = ignored_object_properties
        self.ignored_actions = ignored_actions
        # Extract the features and build the vector
        self.extract_features(malware_subject)
        # Calculate the unique features
        self.get_unique_features()

    def create_action_vector(self, action):
        '''Create a vector from a single Action'''
        action_vector = set()
        # Add the Action Name to the set
        if action.name:
            action_vector.add("act:" + action.name.value)
        # Add the Object values to the set
        if action.associated_objects:
            for associated_object in action.associated_objects:
                if associated_object.properties:
                    object_vector = self.deduplicator.get_object_values(associated_object)
                    updated_vector = set()
                    for entry in object_vector:
                        updated_vector.add(entry.replace(',', ';').rstrip('\n'))
                    action_vector.update(updated_vector)
        return action_vector

    def create_dynamic_vectors(self, malware_subject):
        '''Create a vector of unique action/object pairs for an input Malware Subject'''
        action_vectors = []
        # Extract the Bundles from the Malware Subject
        bundles = malware_subject.get_all_bundles()
        for bundle in bundles:
            # Create the vector for each Action
            all_actions = bundle.get_all_actions()
            for action in all_actions:
                action_vector = self.create_action_vector(action)
                if action_vector:
                    action_vectors.append(action_vector)
        return action_vectors

    def extract_features(self, malware_subject):
        '''Extract the dynamic features from the Malware Subject'''
        # Extract the Dynamic (Action) features
        self.dynamic_features = self.create_dynamic_vectors(malware_subject)
        # Prune the Dynamic features
        self.prune_dynamic_features()

    def prune_dynamic_features(self, min_length = 2):
        '''Prune the dynamic features based on ignored Object properties/Actions'''
        pruned_dynamic_features = []
        for dynamic_vector in self.dynamic_features:
            ignore_vector = False
            pruned_vector = set()
            # Do the minimum length check (to prune Actions with no Objects)
            if len(dynamic_vector) < min_length:
                continue
            # Prune any vectors with ignored actions or object properites
            for entity in dynamic_vector:
                split_entity = str(entity).split(':')
                if split_entity[0] == 'act':
                    action_name = split_entity[1]
                    if action_name in self.ignored_actions:
                        ignore_vector = True
                        break
                    else:
                        pruned_vector.add(entity)
                elif split_entity[0] in self.ignored_object_properties:
                    continue
                else:
                    pruned_vector.add(entity)
            if ignore_vector:
                continue
            else:
                pruned_dynamic_features.append(pruned_vector)
            # Update the existing dynamic feature with the pruned versions
            self.dynamic_features = pruned_dynamic_features

    def get_unique_features(self):
        '''Calculates the unique set of dynamic features for the Malware Subject'''
        self.unique_dynamic_features = [x for x in self.dynamic_features if self.dynamic_features.count(x) == 1]

class StaticFeatureVector(object):
    '''Generate a feature vector for a Malware Subject based on its static features'''
    def __init__(self, malware_subject, deduplicator):
        self.deduplicator = deduplicator
        self.static_features = {}
        self.unique_static_features = {}
        # Extract the features and build the vector
        self.extract_features(malware_subject)
        # Calculate the unique features
        self.get_unique_features()

    def create_object_vector(self, object, static_feature_dict, callback_function = None):
        '''Create a vector from a single Object'''
        object_vector = self.deduplicator.get_object_values(object)
        for entity_string in object_vector:
            split_string =  entity_string.split(':')
            feature_path = str(split_string[0])
            feature_value = str(split_string[1]).lower()
            # Test if this is a feature that we want to keep
            if feature_path in static_features_dict.keys():
                feature_dict = static_features_dict[feature_path]
                feature_name = feature_dict['feature_name']
                # Set the key in the object feature dictionary
                if feature_name in static_feature_dict:
                    # Test if multiple values are allowed for this feature
                    if 'options' in feature_dict and 'allow_multiple' in feature_dict['options']:
                        if isinstance(static_feature_dict[feature_name], list):
                            static_feature_dict[feature_name].append(feature_value)
                        else:
                                static_feature_dict[feature_name] = [static_feature_dict[feature_name], feature_value]
                    # If they're not allowed, use a callback function to determine what to do
                    # E.g., if two different tools report the same value differently, this can be used to resolve that
                    # Callback function parameters : feature name, existing feature value, new feature value
                    elif callback_function:
                        existing_value = static_feature_dict[feature_name]
                        static_feature_dict[feature_name] = callback_function(feature_name, existing_value, feature_value) 

                else:
                    static_feature_dict[feature_name] = feature_value

    def create_static_vectors(self, malware_subject):
        '''Create a vector of static features for an input Malware Subject'''
        static_feature_dict = {}
        # Extract any feature from the Malware Instance Object Attributes of the Malware Subject
        if malware_subject.malware_instance_object_attributes and malware_subject.malware_instance_object_attributes.properties:
            # Add the properties of the Object to the feature dict
            self.create_object_vector(malware_subject.malware_instance_object_attributes, static_feature_dict)
        # Extract any feature from the Bundles in the Malware Subject
        bundles = malware_subject.get_all_bundles()
        for bundle in bundles:
            # Test the Bundle's content_type to make sure we're dealing with static analysis tool output
            if bundle.content_type and bundle.content_type == 'static analysis tool output':
                # Extract the Objects from the Bundle
                for obj in bundle.get_all_objects():
                    if obj.properties:
                        # Add the properties of the Object to the feature dict
                        self.create_object_vector(obj, static_feature_dict)
        if static_feature_dict:
            return static_feature_dict

    def extract_features(self, malware_subject):
        '''Extract the static features from the Malware Subject'''
        # Extract the Static features
        self.static_features = self.create_static_vectors(malware_subject)

    def get_unique_features(self):
        '''Calculates the unique set of static features for the Malware Subject'''
        self.unique_static_features = {}
        for feature_name, feature_value in self.static_features.items():
            # Prune any list-type values
            if isinstance(feature_value, list):
                pruned_value_list = []
                for value in feature_value:
                    if value not in pruned_value_list:
                        pruned_value_list.append(value)
                self.unique_static_features[feature_name] = pruned_value_list
            else:
                self.unique_static_features[feature_name] = feature_value

class Distance(object):
    '''Calculates distance between two or more MAEC entities.
       Currently supports only Packages or Malware Subjects.'''
    def __init__(self, maec_entity_list):
        self.maec_entity_list = maec_entity_list
        # Options dictionary
        # currently available options:
        # use_dynamic_features : True/False. Use dynamic features (Actions) in the distance calculation.
        # use_static_features : True/False. Use static features (File/PE attributes) in the distance calculation.
        self.options_dict = {'use_dynamic_features' : True,
                             'use_static_features' : True}
        self.deduplicator = BundleDeduplicator()
        self.feature_vectors = {}
        self.superset_dynamic_vectors = []
        self.superset_static_vectors = {}
        # A list of normalized/merged Malware Subjects
        self.normalized_subjects = []
        # Dictionary of distances
        # Key = Malware Subject ID
        # Value = dictionary of distances
        #     key = Malware Subject ID
        #     value = distance
        self.distances = {}
        # Dictionary of static features to use in the distance calculation
        # Also, defines how they should be post-processed/compared
        # NOTE: The default features here are merely a suggestion!
        # Options:
        # datatype = Required. The datatype of the values for the feature.
        #            Possible values: hex, hex list, int, int list, float, float list, string.
        # normalize = Optional. Normalize/scale the data.
        #             True by default.
        # scale_log = Optional. Use logarithmic scaling for the list of numeric features.
        #             True by default.
        # bin = Optional. For numerical features, use bins for the distance measure.
        # number of bins = Optional. Valid only if bin = true. The number of bins to use in binning.
        # use_raw_value = Optional. Use the raw value for the field, without any post-processing.
        #                           All other options are ignored when this setting is used.
        self.compared_static_features = {'imported_files' : {'datatype' : 'string'},
                                         'section_entropies' : {'datatype' : 'float list', 'scale log' : False},
                                         'section_virtual_sizes' : {'datatype' : 'hex list','scale log' : False},
                                         'address_of_entry_point' : {'datatype' : 'hex', 'scale log' : False, 'bin' : True},
                                         'size_in_bytes' : {'datatype' : 'int', 'bin' : True},
                                         'size_of_initialized_data' : {'datatype' : 'hex', 'scale log' : False, 'bin' : True, 'number of bins' : 5},
                                         'size_of_image' : {'datatype' : 'hex', 'bin' : True}}
        # List of ignored object attributes, for use in dynamic vector creation
        self.ignored_object_properties = ['address',
                                          'hashes/simple_hash_value',
                                          'id_',
                                          'type_',
                                          'pid',
                                          'size_in_bytes']
        # List of ignored actions (not useful/difficult to correlate on), for use in dynamic vector creation
        self.ignored_actions = ['map view of section',
                                'create section',
                                'create thread',
                                'open section']

    def bin_list(self, numeric_value, numeric_list, n=10):
        '''Bin a numeric value into a bucket, based on a parent list of values.
           N = number of buckets to use (default = 10).'''
        bin_vector = numpy.array([0] * n)
        # Sanity checking for lists with a single value
        if len(numeric_list) == 1:
            bin_vector = numpy.array([0] * n)
            bin_vector[n-1] = 1
            return bin_vector
        max_list = max(numeric_list)
        min_list = min(numeric_list)
        bucket_size = (max_list-min_list)/n        
        bin_value = int(math.floor((numeric_value - min_list)/bucket_size))
        if bin_value == n:
            bin_value -= 1
        bin_vector[bin_value] = 1
        return bin_vector

    def add_log(self, number, log_list):
        '''Added a log'd (log-ized??) number to a list'''
        if number != 0:
            log_list.append(float(math.log(number)))
        else:
            log_list.append(float(number))

    def normalize_numeric(self, numeric_value, numeric_list, normalize = True, scale_log = True):
        '''Scale a numeric value, based on a parent list of values.
           Return the scaled/normalized form.'''
        # Sanity check for zeros
        if numeric_value == 0:
            return float(0)
        if normalize:
            if scale_log:
                log_list = []
                for number in numeric_list:
                    self.add_log(number, log_list)
                return math.log(float(numeric_value))/max(log_list)
            else:
                return float(numeric_value)/max(numeric_list)
        else:
            return numeric_value

    def normalize_numeric_list(self, value_list, numeric_list, normalize = True, scale_log = True):
        '''Scale a list of numeric values, based on a parent list of numeric value lists.
           Return the scaled/normalized form.'''
        # Find the maximum length of all of the lists
        max_len = max(len(p) for p in numeric_list)
        if normalize:
            # Find the maximum value in all of the lists
            max_val = max(max(p) for p in numeric_list)
            if scale_log:
                log_list = []
                for vector_entry in value_list:
                    self.add_log(vector_entry, log_list)
                # Scale the list
                scaled_list = [float(x)/math.log(max_val) for x in log_list]
                scaled_vector = numpy.array(scaled_list)
                # Resize the vector
                scaled_vector.resize(max_len, refcheck = False)
                return scaled_vector
            else:
                # Scale the list
                scaled_list = [float(x)/max_val for x in value_list]
                scaled_vector = numpy.array(scaled_list)
                # Resize the vector
                scaled_vector.resize(max_len, refcheck = False)
                return scaled_vector
        else:
            # Resize the vector
            return value_list.resize(max_len, refcheck = False)

    def build_string_vector(self, string_list, superset_string_list, ignore_case = True):
        '''Build a vector from an input list of strings and superset list of strings.'''
        # Flatten the superset list
        flattened_string_list = self.flatten_vector(superset_string_list)
        # List of ignored/skipped strings
        ignored_strings = ['none']
        # List of unique strings
        unique_strings = []
        # First, build up the unique strings
        for string in flattened_string_list:
            normalized_string = string
            # Ignore case if specified
            if ignore_case:
                normalized_string = string.lower()
            if normalized_string not in ignored_strings and normalized_string not in unique_strings:
                unique_strings.append(normalized_string)
        # Next, build the actual strings vector
        string_vector = numpy.array([0] * len(unique_strings))
        normalized_string_list = string_list
        # Ignore case if specified
        if ignore_case:
            normalized_string_list = [str(x).lower() for x in string_list]
        for i in range(0, len(unique_strings)):
            if unique_strings[i] in normalized_string_list:
                string_vector[i] = 1
            else:
                string_vector[i] = 0
        return string_vector

    def preprocess_entities(self, dereference = True):
        '''Pre-process the MAEC entities'''
        malware_subjects = []
        # Dereference and normalize the Malware Subjects in the Package
        for entity in self.maec_entity_list:
            # Test if we're dealing with a package or Malware Subject
            if isinstance(entity, Package):
                action_vectors = []
                for malware_subject in entity.malware_subjects:
                    # Dereference the Bundles in the Malware Subject
                    if dereference:
                        malware_subject.dereference_bundles()
                    # Normalize the Bundles in the Malware Subject
                    malware_subject.normalize_bundles()
                    # Add the Malware Subject to the list
                    malware_subjects.append(malware_subject)
            elif isinstance(entity, MalwareSubject):
                # Dereference the Bundles in the Malware Subject
                if dereference:
                    entity.dereference_bundles()
                # Normalize the Bundles in the Malware Subject
                entity.normalize_bundles()
                # Add the Malware Subject to the list
                malware_subjects.append(malware_subject)
        # Merge the Malware Subjects by hash (if possible)
        return merge_malware_subjects(malware_subjects)

    def generate_feature_vectors(self, merged_subjects):
        '''Generate a feature vector for the binned Malware Subjects'''
        for malware_subject in merged_subjects:
            feature_vector_dict = {'dynamic' : DynamicFeatureVector(malware_subject, self.deduplicator, self.ignored_object_properties, self.ignored_actions),
                                   'static' : StaticFeatureVector(malware_subject, self.deduplicator)}
            self.feature_vectors[malware_subject.id_] = feature_vector_dict

    def flatten_vector(self, vector_entry_list):
        '''Generate a single, flattened vector from an input list of vectors or values.'''
        component_list = []
        for vector_entry in vector_entry_list:
            if isinstance(vector_entry, numpy.ndarray) or isinstance(vector_entry, list):
                for component in vector_entry:
                    component_list.append(component)
            else:
                component_list.append(vector_entry)
        return component_list

    def normalize_vectors(self, vector_1, vector_2):
        '''Normalize two input vectors so that they have similar composition.'''
        for i in range(0, len(vector_1)):
            if type(vector_1[i]) != type(vector_2[i]):
                if isinstance(vector_1[i], numpy.ndarray) and not isinstance(vector_2[i], numpy.ndarray):
                    vector_2[i] = numpy.array([0] * len(vector_1[i]))
                elif not isinstance(vector_1[i], numpy.ndarray) and isinstance(vector_2[i], numpy.ndarray):
                    vector_1[i] = numpy.array([0] * len(vector_2[i]))

    def create_static_result_vector(self, static_vector):
        '''Construct the static result (matching) vector for a corresponding feature vector'''
        results_vector = []
        for feature_name in self.compared_static_features:
            # Test if we wish to use the feature in the comparison
            if feature_name in static_vector.unique_static_features:
                # Get the value of the feature
                feature_value = static_vector.unique_static_features[feature_name]
                # Get the options dictionary for the feature
                feature_options_dict = self.compared_static_features[feature_name]
                feature_items = self.superset_static_vectors[feature_name]
                # Check if the raw value setting is specified
                if 'use_raw_value' in feature_options_dict:
                    results_vector.append(feature_value)
                    continue
                # Determine if numeric values should be logarithmically scaled - true by default
                scale_log = True
                if 'scale log' in feature_options_dict:
                    scale_log = feature_options_dict['scale log']
                # Determine if numeric values should be normalized - true by default
                normalize = True
                if 'normalize' in feature_options_dict:
                    normalize = feature_options_dict['normalize']
                # Normalize the items for the feature based on the specified datatype
                # Use this to construct the results vector
                # Normalize on hex values
                normalized_value = None
                if feature_options_dict['datatype'] == 'hex':
                    converted_types = [int(x,0) for x in feature_items]
                    normalized_value = self.normalize_numeric(int(feature_value,0), converted_types, normalize, scale_log)
                # Normalize on lists of hex values
                if feature_options_dict['datatype'] == 'hex list':
                    converted_types = [numpy.array([int(x, 0) for x in y]) for y in feature_items]
                    normalized_value = self.normalize_numeric_list(numpy.array([int(x,0) for x in feature_value]), converted_types, normalize, scale_log)
                # Normalize on int values
                elif feature_options_dict['datatype'] == 'int':
                    converted_types = [int(x) for x in feature_items]
                    normalized_value = self.normalize_numeric(int(feature_value), converted_types, normalize, scale_log)
                # Normalize on lists of int values
                elif feature_options_dict['datatype'] == 'int list':
                    converted_types = [numpy.array([int(x) for x in y]) for y in feature_items]
                    normalized_value = self.normalize_numeric_list(numpy.array([int(x) for x in feature_value]), converted_types, normalize, scale_log)
                # Normalize on float values
                elif feature_options_dict['datatype'] == 'float':
                    converted_types = [float(x) for x in feature_items]
                    normalized_value = self.normalize_numeric(float(feature_value), converted_types, normalize, scale_log)
                # Normalize on lists of float values
                elif feature_options_dict['datatype'] == 'float list':
                    converted_types = [numpy.array([float(x) for x in y]) for y in feature_items]
                    normalized_value = self.normalize_numeric_list(numpy.array([float(x) for x in feature_value]), converted_types, normalize, scale_log)
                # Normalize on string values
                elif feature_options_dict['datatype'] == 'string':
                    string_vector = self.build_string_vector(feature_value, feature_items)
                    results_vector.append(string_vector)
                # Bin any values, if specified in the options dictionary
                if 'bin' in feature_options_dict and feature_options_dict['bin']:
                    normalized_items = [self.normalize_numeric(x, converted_types, scale_log) for x in converted_types]
                    if 'number of bins' in feature_options_dict:
                        bin = self.bin_list(normalized_value, normalized_items, feature_options_dict['number of bins'])
                    else:
                        bin = self.bin_list(normalized_value, normalized_items)
                    results_vector.append(bin)                
                elif normalized_value is not None:
                    results_vector.append(normalized_value)
            else:
                results_vector.append(0)
        return results_vector

    def create_dynamic_result_vector(self, dynamic_vector):
        '''Construct the dynamic result (matching) vector for a corresponding feature vector'''
        # First, construct the results vector for the dynamic vectors
        results_vector = numpy.array([0] * len(self.superset_dynamic_vectors))
        i = 0
        for vector in self.superset_dynamic_vectors:
            if vector in dynamic_vector.unique_dynamic_features:
                results_vector[i] = 1
            i+= 1
        return results_vector

    def create_superset_vectors(self):
        '''Calculate vector supersets from the feature vectors'''
        for feature_vector_dict in self.feature_vectors.values():
            dynamic_vector = feature_vector_dict['dynamic']
            static_vector = feature_vector_dict['static']
            # Build the superset of dynamic vectors
            for vector in dynamic_vector.unique_dynamic_features:
                if vector not in self.superset_dynamic_vectors:
                    self.superset_dynamic_vectors.append(vector)
            # Build the superset of static vectors
            for feature_name, feature_value in static_vector.unique_static_features.items():
                if feature_name not in self.superset_static_vectors:
                    self.superset_static_vectors[feature_name] = [feature_value]
                else:
                    self.superset_static_vectors[feature_name].append(feature_value)

    def euclidean_distance(self, vector_1, vector_2):
        '''Calculate the Euclidean distance between two input vectors'''
        distance = 0.0
        for i in range(0, len(vector_1)):
            if isinstance(vector_1[i], float):
                distance += math.pow(vector_1[i] - vector_2[i], 2)
            elif isinstance(vector_1[i], numpy.ndarray):
                for vi in range(0, len(vector_1[i])):
                    distance += math.pow(vector_1[i][vi] - vector_2[i][vi], 2)
            elif isinstance(vector_1[i], int):
                if vector_1[i] != vector_2[i]:
                    distance += 1.0
            elif isinstance(vector_1[i], str):
                if vector_1[i] != vector_2[i]:
                    distance += 1.0
        return math.sqrt(distance)

    def populate_hashes_mapping(self, malware_subject_list):
        '''Populate and return the Malware Subject -> Hashes mapping from an input list of Malware Subjects.'''
        hashes_mapping = {}
        for malware_subject in malware_subject_list:
            mal_inst_obj = malware_subject.malware_instance_object_attributes
            if mal_inst_obj.properties and mal_inst_obj.properties.hashes:
                hashes_dict = {}
                for hash in mal_inst_obj.properties.hashes:
                    type = None
                    value = None
                    if hash.type_:
                        type = hash.type_.value
                    if hash.simple_hash_value:
                        value = hash.simple_hash_value.value
                    elif hash.fuzzy_hash_value:
                        value = hash.fuzzy_hash_value.value
                    if type and value:
                        hashes_dict[str(type).lower()] = str(value).lower()
                hashes_mapping[malware_subject.id_] = hashes_dict
        return hashes_mapping

    def perform_calculation(self):
        '''Perform the actual distance calculation.
           Store the results in the distances dictionary.'''
        # Determine the different combinations of Malware Subjects
        combinations = itertools.combinations(self.feature_vectors, r=2)
        for combination in combinations:
            if self.options_dict['use_dynamic_features']:
                dynamic_vectors = (self.feature_vectors[combination[0]]['dynamic_result'],
                                   self.feature_vectors[combination[1]]['dynamic_result'])
            if self.options_dict['use_static_features']:
                static_vectors = (self.feature_vectors[combination[0]]['static_result'],
                                   self.feature_vectors[combination[1]]['static_result'])
                # Normalize the static vectors (to make them equal length)
                self.normalize_vectors(static_vectors[0], static_vectors[1])
            # Generate the combined vectors if necessary and calculate the distance
            if self.options_dict['use_dynamic_features'] and self.options_dict['use_static_features']:
                result_vectors = (numpy.array(list(dynamic_vectors[0]) + self.flatten_vector(static_vectors[0])),
                                  numpy.array(list(dynamic_vectors[1]) + self.flatten_vector(static_vectors[1])))
            elif self.options_dict['use_dynamic_features'] and not self.options_dict['use_static_features']:
                result_vectors = (numpy.array(list(dynamic_vectors[0])),
                                  numpy.array(list(dynamic_vectors[1])))
            elif not self.options_dict['use_dynamic_features'] and self.options_dict['use_static_features']:
                result_vectors = (self.flatten_vector(static_vectors[0]),
                                  self.flatten_vector(static_vectors[1]))
            distance = self.euclidean_distance(result_vectors[0], result_vectors[1])
            # Add the result to the distances dictionary
            for i in range(0,2):
                opposite = 1 - i
                if combination[i] not in self.distances:
                    self.distances[combination[i]] = {combination[opposite] : distance}
                else:
                    self.distances[combination[i]][combination[opposite]] = distance

    def calculate(self):
        '''Calculate the distances between the input Malware Subjects.'''
        # Pre-process and merge the entities
        self.normalized_subjects = self.preprocess_entities()
        # Generate the feature vectors for the entities
        self.generate_feature_vectors(self.normalized_subjects)
        # Build up the supersets of unique vectors
        self.create_superset_vectors()
        # Construct the result vectors
        for feature_vector_dict in self.feature_vectors.values():
            if self.options_dict['use_dynamic_features']:
                # Construct the dynamic result vector
                feature_vector_dict['dynamic_result'] = self.create_dynamic_result_vector(feature_vector_dict['dynamic'])
            if self.options_dict['use_static_features']:
                # Construct the static result vector
                feature_vector_dict['static_result'] = self.create_static_result_vector(feature_vector_dict['static'])
        # Perform the actual distance calculation
        self.perform_calculation()

    def print_distances(self, file_object, default_label = 'md5', delimiter = ','):
        '''Print the distances between the Malware Subjects in delimited matrix format 
           to a File-like object.

           Try to use the MD5s of the Malware Subjects as the default label.
           Uses commas as the default delimiter, for CSV-like output.'''
        hashes_mapping = self.populate_hashes_mapping(self.normalized_subjects)
        distance_strings = []
        # Generate the header string and individual distance strings
        header_string = '' + delimiter
        for malware_subject in self.normalized_subjects:
            distance_string = ''
            hashes = hashes_mapping[malware_subject.id_]
            if default_label in hashes:
                distance_string += (hashes[default_label] + delimiter)
                header_string += (hashes[default_label] + delimiter)
            else:
                distance_string += (malware_subject.id_ + delimiter)
                header_string += (malware_subject.id_ + delimiter)
            for other_malware_subject in self.normalized_subjects:
                if malware_subject.id_ == other_malware_subject.id_:
                    distance_string += ('0.0' + delimiter)
                else:
                    distance_string += (str(self.distances[malware_subject.id_][other_malware_subject.id_])
                                        + delimiter)
            distance_strings.append(distance_string.rstrip(delimiter))

        # Print the header and distance strings
        file_object.write(header_string.rstrip(delimiter) + "\n")
        for distance_string in distance_strings:
            file_object.write(distance_string + "\n")
        file_object.flush()


