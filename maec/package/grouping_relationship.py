# MAEC Grouping Relationship Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

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
    
    similarity_index = fields.TypedField("similarity_index")
    similarity_distance = fields.TypedField("similarity_distance")
    malware_subject_node_a = fields.TypedField("Malware_Subject_Node_A", MalwareSubjectReference)
    malware_subject_node_b = fields.TypedField("Malware_Subject_Node_B", MalwareSubjectReference)

    def __init__(self):
        super(ClusterEdgeNodePair, self).__init__()

class ClusterComposition(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusterCompositionType
    _namespace = _namespace
    
    score_type = fields.TypedField("score_type")
    edge_node_pair = fields.TypedField("Edge_Node_Pair", ClusterEdgeNodePair, multiple=True)

    def __init__(self):
        super(ClusterComposition, self).__init__()

class ClusteringAlgorithmParameters(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusteringAlgorithmParametersType
    _namespace = _namespace

    distance_threashold = fields.TypedField("Distance_Threashold")
    number_of_iterations = fields.TypedField("Number_of_Iterations")

    def __init__(self):
        super(ClusteringAlgorithmParameters, self).__init__()

class ClusteringMetadata(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.ClusteringMetadataType
    _namespace = _namespace

    algorithm_name = fields.TypedField("Algorithm_Name")
    algorithm_version = fields.TypedField("Algorithm_Version")
    algorithm_parameters = fields.TypedField("Algorithm_Parameters", ClusteringAlgorithmParameters)
    cluster_size = fields.TypedField("Cluster_Size")
    cluster_description = fields.TypedField("Cluster_Description")
    cluster_composition = fields.TypedField("Cluster_Composition", ClusterComposition)

    def __init__(self):
        super(ClusteringMetadata, self).__init__()

class GroupingRelationship(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.GroupingRelationshipType
    _namespace = _namespace

    type_ = vocabs.VocabField("Type", GroupingRelationshipVocab)
    malware_family_name = fields.TypedField("Malware_Family_Name")
    malware_toolkit_name = fields.TypedField("Malware_Toolkit_Name")
    clustering_metadata = fields.TypedField("Clustering_Metadata", ClusteringMetadata)

    def __init__(self):
        super(GroupingRelationship, self).__init__()

class GroupingRelationshipList(maec.EntityList):
    _contained_type = GroupingRelationship
    _binding_class = package_binding.GroupingRelationshipListType
    _binding_var = "Grouping_Relationship"
    _namespace = _namespace




