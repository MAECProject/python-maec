#MAEC Grouping Relationship Class

#Copyright (c) 2014, The MITRE Corporation
#All rights reserved

#Compatible with MAEC v4.1
#Last updated 08/20/2014

import cybox
import maec
import maec.bindings.maec_package as package_binding  
from maec.package.malware_subject_reference import MalwareSubjectReference
from cybox.common import VocabString

class ClusterEdgeNodePair(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusterEdgeNodePairType
    _namespace = maec.package._namespace
    
    similarity_index = cybox.TypedField("similarity_index")
    similarity_distance = cybox.TypedField("similarity_distance")
    malware_subject_node_a = cybox.TypedField("malware_subject_node_a", MalwareSubjectReference)
    malware_subject_node_b = cybox.TypedField("malware_subject_node_b", MalwareSubjectReference)

    def __init__(self):
        super(ClusterEdgeNodePair, self).__init__()
        self.similarity_index = None
        self.similarity_distance = None
        self.malware_subject_node_a = None
        self.malware_subject_node_b = None

class ClusterComposition(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusterCompositionType
    _namespace = maec.package._namespace
    
    score_type = cybox.TypedField("score_type")
    edge_node_pair = cybox.TypedField("edge_node_pair", ClusterEdgeNodePair, multiple=True)

    def __init__(self):
        super(ClusterComposition, self).__init__()
        self.score_type = None
        self.edge_node_pair = []

class ClusteringAlgorithmParameters(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusteringAlgorithmParametersType
    _namespace = maec.package._namespace

    distance_threashold = cybox.TypedField("distance_threashold")
    number_of_iterations = cybox.TypedField("number_of_iterations")

    def __init__(self):
        super(ClusteringAlgorithmParameters, self).__init__()
        self.distance_threshold = None
        self.number_of_iterations = None

class ClusteringMetadata(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusteringMetadataType
    _namespace = maec.package._namespace

    algorithm_name = cybox.TypedField("algorithm_name")
    algorithm_version = cybox.TypedField("algorithm_version")
    algorithm_parameters = cybox.TypedField("algorithm_parameters", ClusteringAlgorithmParameters)
    cluster_size = cybox.TypedField("cluster_size")
    cluster_description = cybox.TypedField("cluster_description")
    cluster_composition = cybox.TypedField("cluster_composition", ClusterComposition)

    def __init__(self):
        super(ClusteringMetadata, self).__init__()
        self.algorithm_name = None
        self.algorithm_version = None
        self.algorithm_parameters = None
        self.cluster_size = None
        self.cluster_description = None
        self.cluster_composition = None

class GroupingRelationship(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.GroupingRelationshipType
    _namespace = maec.package._namespace

    type = cybox.TypedField("type")
    malware_family_name = cybox.TypedField("malware_family_name")
    malware_toolkit_name = cybox.TypedField("malware_toolkit_name")
    clustering_metadata = cybox.TypedField("clustering_metadata", ClusteringMetadata)

    def __init__(self):
        super(GroupingRelationship, self).__init__()
        self.type = None
        self.malware_family_name = None
        self.malware_toolkit_name = None
        self.clustering_metadata = None

class GroupingRelationshipList(maec.EntityList):
    _contained_type = GroupingRelationship
    _binding_class = package_binding.GroupingRelationshipListType
    _binding_var = "Grouping_Relationship"
    _namespace = maec.package._namespace




