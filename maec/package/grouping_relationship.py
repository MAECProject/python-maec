# MAEC Grouping Relationship Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved


import maec
from . import _namespace
import maec.bindings.maec_package as package_binding  
from maec.package.malware_subject_reference import MalwareSubjectReference
from cybox.common import vocabs
from maec.vocabs.vocabs import GroupingRelationship as GroupingRelationshipVocab

class ClusterEdgeNodePair(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusterEdgeNodePairType
    _namespace = _namespace
    
    similarity_index = maec.TypedField("similarity_index")
    similarity_distance = maec.TypedField("similarity_distance")
    malware_subject_node_a = maec.TypedField("Malware_Subject_Node_A", MalwareSubjectReference)
    malware_subject_node_b = maec.TypedField("Malware_Subject_Node_B", MalwareSubjectReference)

    def __init__(self):
        super(ClusterEdgeNodePair, self).__init__()

class ClusterComposition(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusterCompositionType
    _namespace = _namespace
    
    score_type = maec.TypedField("score_type")
    edge_node_pair = maec.TypedField("Edge_Node_Pair", ClusterEdgeNodePair, multiple=True)

    def __init__(self):
        super(ClusterComposition, self).__init__()

class ClusteringAlgorithmParameters(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusteringAlgorithmParametersType
    _namespace = _namespace

    distance_threashold = maec.TypedField("Distance_Threashold")
    number_of_iterations = maec.TypedField("Number_of_Iterations")

    def __init__(self):
        super(ClusteringAlgorithmParameters, self).__init__()

class ClusteringMetadata(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusteringMetadataType
    _namespace = _namespace

    algorithm_name = maec.TypedField("Algorithm_Name")
    algorithm_version = maec.TypedField("Algorithm_Version")
    algorithm_parameters = maec.TypedField("Algorithm_Parameters", ClusteringAlgorithmParameters)
    cluster_size = maec.TypedField("Cluster_Size")
    cluster_description = maec.TypedField("Cluster_Description")
    cluster_composition = maec.TypedField("Cluster_Composition", ClusterComposition)

    def __init__(self):
        super(ClusteringMetadata, self).__init__()

class GroupingRelationship(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.GroupingRelationshipType
    _namespace = _namespace

    type_ = vocabs.VocabField("Type", GroupingRelationshipVocab)
    malware_family_name = maec.TypedField("Malware_Family_Name")
    malware_toolkit_name = maec.TypedField("Malware_Toolkit_Name")
    clustering_metadata = maec.TypedField("Clustering_Metadata", ClusteringMetadata)

    def __init__(self):
        super(GroupingRelationship, self).__init__()

class GroupingRelationshipList(maec.EntityList):
    _contained_type = GroupingRelationship
    _binding_class = package_binding.GroupingRelationshipListType
    _binding_var = "Grouping_Relationship"
    _namespace = _namespace




