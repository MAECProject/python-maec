#MAEC Grouping Relationship Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/15/2013

import maec
import maec.bindings.maec_package as package_binding  
from maec.package.malware_subject_reference import MalwareSubjectReference
from cybox.common import VocabString

class GroupingRelationship(maec.Entity):

    def init(self):
        super(GroupingRelationship, self).__init__()
        self.type = None
        self.malware_family_name = None
        self.malware_toolkit_name = None
        self.clustering_metadata = None

    def to_obj(self):
        grouping_relationship_obj = package_binding.GroupingRelationshipType()
        if self.type is not None : grouping_relationship_obj.set_Type(self.type.to_obj())
        if self.malware_family_name is not None : grouping_relationship_obj.set_Malware_Family_Name(self.malware_family_name)
        if self.malware_toolkit_name is not None : grouping_relationship_obj.set_Malware_Toolkit_Name(self.malware_toolkit_name)
        if self.clustering_metadata is not None : grouping_relationship_obj.set_Clustering_Metadata(self.clustering_metadata.to_obj())
        return grouping_relationship_obj

    def to_dict(self):
        grouping_relationship_dict = {}
        if self.type is not None : grouping_relationship_dict['type'] = self.type.to_dict()
        if self.malware_family_name is not None : grouping_relationship_dict['malware_family_name'] = self.malware_family_name
        if self.malware_toolkit_name is not None : grouping_relationship_dict['malware_toolkit_name'] = self.malware_family_name
        if self.clustering_metadata is not None : grouping_relationship_dict['clustering_metadata'] = self.clustering_metadata.to_dict()
        return grouping_relationship_dict

    @staticmethod
    def from_dict(grouping_relationship_dict):
        if not grouping_relationship_dict:
            return None
        grouping_relationship_ = GroupingRelationship()
        grouping_relationship_.type = VocabString.from_dict(grouping_relationship_dict.get('type'))
        grouping_relationship_.malware_family_name = grouping_relationship_dict.get('malware_family_name')
        grouping_relationship_.malware_toolkit_name = grouping_relationship_dict.get('malware_toolkit_name')
        grouping_relationship_.clustering_metadata = ClusteringMetadata.from_dict(grouping_relationship_dict.get('clustering_metadata'))
        return grouping_relationship_

    @staticmethod
    def from_obj(grouping_relationship_obj):
        if not grouping_relationship_obj:
            return None
        grouping_relationship_ = GroupingRelationship()
        grouping_relationship_.type = VocabString.from_obj(grouping_relationship_obj.get_Type())
        grouping_relationship_.malware_family_name = grouping_relationship_obj.get_Malware_Family_Name()
        grouping_relationship_.malware_toolkit_name = grouping_relationship_obj.get_Malware_Toolkit_Name()
        grouping_relationship_.clustering_metadata = ClusteringMetadata.from_obj(grouping_relationship_obj.get_Clustering_Metadata())
        return grouping_relationship_

class GroupingRelationshipList(maec.EntityList):
    _contained_type = GroupingRelationship
    _binding_class = package_binding.GroupingRelationshipListType
    _binding_var = "Grouping_Relationship"

class ClusteringMetadata(maec.Entity):

    def __init__(self):
        super(ClusteringMetadata, self).__init__()
        self.algorithm_name = None
        self.algorithm_version = None
        self.algorithm_parameters = None
        self.cluster_size = None
        self.cluster_description = None
        self.cluster_composition = None

    def to_obj(self):
        clustering_metadata_obj = package_binding.ClusteringMetadataType()
        if self.algorithm_name is not None : clustering_metadata_obj.set_Algorithm_Name(self.algorithm_name)
        if self.algorithm_version is not None : clustering_metadata_obj.set_Algorithm_Version(self.algorithm_version)
        if self.algorithm_parameters is not None : clustering_metadata_obj.set_Algorithm_Parameters(self.algorithm_parameters.to_obj())
        if self.cluster_size is not None : clustering_metadata_obj.set_Cluster_Size(self.cluster_size)
        if self.cluster_description is not None : clustering_metadata_obj.set_Cluster_Description(self.cluster_description)
        if self.cluster_composition is not None : clustering_metadata_obj.set_Cluster_Composition(self.cluster_composition.to_obj())
        return clustering_metadata_obj

    def to_dict(self):
        clustering_metadata_dict = {}
        if self.algorithm_name is not None : clustering_metadata_dict['algorithm_name'] = self.algorithm_name
        if self.algorithm_version is not None : clustering_metadata_dict['algorithm_version'] = self.algorithm_version
        if self.algorithm_parameters is not None : clustering_metadata_dict['algorithm_parameters'] = self.algorithm_parameters.to_dict()
        if self.cluster_size is not None : clustering_metadata_dict['cluster_size'] = self.cluster_size
        if self.cluster_description is not None : clustering_metadata_dict['cluster_description'] = self.cluster_description
        if self.cluster_composition is not None : clustering_metadata_dict['cluster_composition'] = self.cluster_composition.to_dict()
        return clustering_metadata_dict

    @staticmethod
    def from_dict(clustering_metadata_dict):
        if not clustering_metadata_dict:
            return None
        clustering_metadata_ = ClusteringMetadata()
        clustering_metadata_.algorithm_name = clustering_metadata_dict.get('algorithm_name')
        clustering_metadata_.algorithm_version = clustering_metadata_dict.get('algorithm_version')
        clustering_metadata_.algorithm_parameters = ClusteringAlgorithmParameters.from_dict(clustering_metadata_dict.get('algorithm_parameters'))
        clustering_metadata_.cluster_size = clustering_metadata_dict.get('cluster_size')
        clustering_metadata_.cluster_description = clustering_metadata_dict.get('cluster_description')
        clustering_metadata_.cluster_composition = ClusterComposition.from_dict(clustering_metadata_dict.get('cluster_composition'))
        return clustering_metadata_

    @staticmethod
    def from_obj(clustering_metadata_obj):
        if not clustering_metadata_obj:
            return None
        clustering_metadata_ = ClusteringMetadata()
        clustering_metadata_.algorithm_name = clustering_metadata_obj.get_Algorithm_Name()
        clustering_metadata_.algorithm_version = clustering_metadata_obj.get_Algorithm_Version()
        clustering_metadata_.algorithm_parameters = ClusteringAlgorithmParameters.from_obj(clustering_metadata_obj.get_Algorithm_Parameters())
        clustering_metadata_.cluster_size = clustering_metadata_obj.get_Cluster_Size()
        clustering_metadata_.cluster_description = clustering_metadata_obj.get_Cluster_Description()
        clustering_metadata_.cluster_composition = ClusterComposition.from_obj(clustering_metadata_obj.get_Cluster_Composition())
        return clustering_metadata_


class ClusteringAlgorithmParameters(maec.Entity):

    def __init__(self):
        super(ClusteringAlgorithmParameters, self).__init__()
        self.distance_threshold = None
        self.number_of_iterations = None

    def to_obj(self):
        clustering_algorithm_parameters_obj = package_binding.ClusteringAlgorithmParametersType()
        if self.distance_threshold is not None : clustering_algorithm_parameters_obj.set_Distance_Threshold(self.distance_threshold)
        if self.number_of_iterations is not None : clustering_algorithm_parameters_obj.set_Number_of_Iterations(self.number_of_iterations)
        return clustering_algorithm_parameters_obj

    def to_dict(self):
        clustering_algorithm_parameters_dict = {}
        if self.distance_threshold is not None : clustering_algorithm_parameters_dict['distance_threshold'] = self.distance_threshold
        if self.number_of_iterations is not None : clustering_algorithm_parameters_dict['number_of_iterations'] = self.number_of_iterations
        return clustering_algorithm_parameters_dict

    @staticmethod
    def from_dict(clustering_algorithm_parameters_dict):
        if not clustering_algorithm_parameters_dict:
            return None
        clustering_algorithm_parameters_ = ClusteringAlgorithmParameters()
        clustering_algorithm_parameters_.distance_threshold = clustering_algorithm_parameters_dict.get('distance_threshold')
        clustering_algorithm_parameters_.number_of_iterations = clustering_algorithm_parameters_dict.get('number_of_iterations')
        return clustering_algorithm_parameters_

    @staticmethod
    def from_obj(clustering_algorithm_parameters_obj):
        if not clustering_algorithm_parameters_obj:
            return None
        clustering_algorithm_parameters_ = ClusteringAlgorithmParameters()
        clustering_algorithm_parameters_.distance_threshold = clustering_algorithm_parameters_obj.get_Distance_Threshold()
        clustering_algorithm_parameters_.number_of_iterations = clustering_algorithm_parameters_obj.get_Number_of_Iterations()
        return clustering_algorithm_parameters_

class ClusterComposition(maec.Entity):

    def __init__(self):
        super(ClusterComposition, self).__init__()
        self.score_type = None
        self.edge_node_pairs = []

    def to_obj(self):
        cluster_composition_obj = package_binding.ClusterCompositionType()
        if self.score_type is not None : cluster_composition_obj.set_score_type(self.score_type)
        if len(edge_node_pairs) > 0:
            for edge_node_pair in self.edge_node_pairs: cluster_composition_obj.add_Edge_Node_Pair(edge_node_pair.to_obj())
        return cluster_composition_obj

    def to_dict(self):
        cluster_composition_dict = {}
        if self.score_type is not None : cluster_composition_dict['score_type'] = self.score_type
        if len(edge_node_pairs) > 0:
            for edge_node_pair in self.edge_node_pairs: cluster_composition_obj.add_Edge_Node_Pair(edge_node_pair.to_obj())
        return cluster_composition_dict

    @staticmethod
    def from_dict(cluster_composition_dict):
        if not cluster_composition_dict:
            return None
        cluster_composition_ = ClusterComposition()
        cluster_composition_.score_type = cluster_composition_dict.get('score_type')
        cluster_composition_.edge_node_pairs = [ClusterEdgeNodePair.from_dict(x) for x in cluster_composition_dict.get('edge_node_pairs',[])]
        return cluster_composition_

    @staticmethod
    def from_obj(cluster_composition_obj):
        if not cluster_composition_obj:
            return None
        cluster_composition_ = ClusterComposition()
        cluster_composition_.score_type = cluster_composition_obj.get_score_type()
        cluster_composition_.edge_node_pairs = [ClusterEdgeNodePair.from_obj(x) for x in cluster_composition_obj.get_Edge_Node_Pair()]
        return cluster_composition_

class ClusterEdgeNodePair(maec.Entity):

    def __init__(self):
        super(ClusterEdgeNodePair, self).__init__()
        self.similarity_index = None
        self.similarity_distance = None
        self.malware_subject_node_a = None
        self.malware_subject_node_b = None

    def to_obj(self):
        cluster_edge_node_pair_obj = package_binding.ClusterEdgeNodePairType()
        if self.similarity_index is not None : cluster_edge_node_pair_obj.set_similarity_index(self.similarity_index)
        if self.similarity_distance is not None : cluster_edge_node_pair_obj.set_similarity_distance(self.similarity_distance)
        if self.malware_subject_node_a is not None : cluster_edge_node_pair_obj.set_Malware_Subject_Node_A(self.malware_subject_node_a.to_obj())
        if self.malware_subject_node_b is not None : cluster_edge_node_pair_obj.set_Malware_Subject_Node_B(self.malware_subject_node_b.to_obj())
        return cluster_edge_node_pair_obj

    def to_dict(self):
        cluster_edge_node_pair_dict = {}
        if self.similarity_index is not None : cluster_edge_node_pair_dict['similarity_index'] = self.similarity_index
        if self.similarity_distance is not None : cluster_edge_node_pair_dict['similarity_distance'] = self.similarity_distance
        if self.malware_subject_node_a is not None : cluster_edge_node_pair_dict['malware_subject_node_a'] = self.malware_subject_node_a.to_dict()
        if self.malware_subject_node_b is not None : cluster_edge_node_pair_dict['malware_subject_node_b'] = self.malware_subject_node_b.to_dict()
        return cluster_edge_node_pair_dict

    @staticmethod
    def from_dict(cluster_edge_node_pair_dict):
        if not cluster_edge_node_pair_dict:
            return None
        cluster_edge_node_pair_ = ClusterEdgeNodePair()
        cluster_edge_node_pair_.similarity_index = cluster_edge_node_pair_dict.get('similarity_index')
        cluster_edge_node_pair_.similarity_distance = cluster_edge_node_pair_dict.get('similarity_distance')
        cluster_edge_node_pair_.malware_subject_node_a = MalwareSubjectReference.from_dict(cluster_edge_node_pair_dict.get('malware_subject_node_a'))
        cluster_edge_node_pair_.malware_subject_node_b = MalwareSubjectReference.from_dict(cluster_edge_node_pair_dict.get('malware_subject_node_b'))
        return cluster_edge_node_pair_

    @staticmethod
    def from_obj(cluster_edge_node_pair_obj):
        if not cluster_edge_node_pair_obj:
            return None
        cluster_edge_node_pair_ = ClusterEdgeNodePair()
        cluster_edge_node_pair_.similarity_index = cluster_edge_node_pair_obj.get_similarity_index()
        cluster_edge_node_pair_.similarity_distance = cluster_edge_node_pair_obj.get_similarity_distance()
        cluster_edge_node_pair_.malware_subject_node_a = MalwareSubjectReference.from_obj(cluster_edge_node_pair_obj.get_Malware_Subject_Node_A())
        cluster_edge_node_pair_.malware_subject_node_b = MalwareSubjectReference.from_obj(cluster_edge_node_pair_obj.get_Malware_Subject_Node_B())
        return cluster_edge_node_pair_
