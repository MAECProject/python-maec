_namespace = 'http://maec.mitre.org/XMLSchema/maec-bundle-4'

import maec
from .malware_action import (MalwareAction, ActionImplementation, APICall,
                             ParameterList, Parameter)
from .av_classification import AVClassification, AVClassifications
from .behavior_reference import BehaviorReference
from .behavior import (Behavior, AssociatedCode, BehaviorPurpose, Exploit,
                       CVEVulnerability, PlatformList, BehavioralActions,
                       BehavioralAction, BehavioralActionReference,
                       BehavioralActionEquivalenceReference)
from .action_reference_list import ActionReferenceList
from .candidate_indicator import (CandidateIndicatorList, CandidateIndicator,
                                  CandidateIndicatorComposition, MalwareEntity)
from .process_tree import ProcessTree, ProcessTreeNode
from .bundle_reference import BundleReference
from .capability import (CapabilityList, Capability, CapabilityObjective,
                         CapabilityProperty, CapabilityRelationship,
                         CapabilityObjectiveRelationship, CapabilityReference,
                         CapabilityObjectiveReference)
from .object_history import ObjectHistoryEntry, ObjectHistory
from .object_reference import ObjectReferenceList, ObjectReference
from .bundle import (Bundle, BehaviorReference, Collections,
                     CandidateIndicatorCollectionList, ObjectCollectionList,
                     ActionCollectionList, BehaviorCollectionList, 
                     CandidateIndicatorCollection, ObjectCollection,
                     BehaviorCollection, ActionCollection, BaseCollection,
                     ObjectList, ActionList, BehaviorList)


