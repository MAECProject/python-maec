# MAEC Capability Classes

# Copyright (c) 2014, The MITRE Corporation
# All rights reserved

# Compatible with MAEC v4.1
# Last updated 8/26/2014

import maec
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle.behavior_reference import BehaviorReference
from cybox.common import VocabString, String

class CapabilityObjectiveReference(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityObjectiveReferenceType

    objective_idref = maec.TypedField("objective_idref")

    def __init__(self):
        super(CapabilityObjectiveReference, self).__init__()
        
class CapabilityReference(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityReferenceType

    capability_idref = maec.TypedField("capability_idref")

    def __init__(self):
        super(CapabilityReference, self).__init__()

class CapabilityObjectiveRelationship(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityObjectiveRelationshipType

    relationship_type = maec.TypedField("Relationship_Type", VocabString)
    objective_reference = maec.TypedField("Objective_Reference", CapabilityObjectiveReference, multiple = True)

    def __init__(self):
        super(CapabilityObjectiveRelationship, self).__init__()
        self.objective_reference = []

class CapabilityRelationship(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityRelationshipType

    relationship_type = maec.TypedField("Relationship_Type", VocabString)
    capability_reference = maec.TypedField("Capability_Reference", CapabilityReference, multiple = True)

    def __init__(self):
        super(CapabilityRelationship, self).__init__()
        self.capability_reference = []

class CapabilityProperty(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityPropertyType

    name = maec.TypedField("Name", VocabString)
    value = maec.TypedField("Value", String)

    def __init__(self):
        super(CapabilityProperty, self).__init__()

class CapabilityObjective(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityObjectiveType

    id_ = maec.TypedField("id")
    name = maec.TypedField("Name", VocabString)
    description = maec.TypedField("Description")
    property = maec.TypedField("Property", CapabilityProperty, multiple = True)
    behavior_reference = maec.TypedField("Behavior_Reference", BehaviorReference, multiple = True)
    relationship = maec.TypedField("Relationship", CapabilityObjectiveRelationship, multiple = True)

    def __init__(self, id = None):
        super(CapabilityObjective, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="capability_objective")

class Capability(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityType

    id_ = maec.TypedField("id")
    name = maec.TypedField("name")
    description = maec.TypedField("Description")
    property = maec.TypedField("Property", CapabilityProperty, multiple = True)
    strategic_objective = maec.TypedField("Strategic_Objective", CapabilityObjective, multiple = True)
    tactical_objective = maec.TypedField("Tactical_Objective", CapabilityObjective, multiple = True)
    behavior_reference = maec.TypedField("Behavior_Reference", BehaviorReference, multiple = True)
    relationship = maec.TypedField("Relationship", CapabilityRelationship, multiple = True)

    def __init__(self, id = None, name = None):
        super(Capability, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="capability")
        self.name = name

    def add_tactical_objective(self, tactical_objective):
        """Add a Tactical Objective to the Capability."""
        if not self.tactical_objective:
            self.tactical_objective = []
        self.tactical_objective.append(tactical_objective)

    def add_strategic_objective(self, strategic_objective):
        """Add a Strategic Objective to the Capability."""
        if not self.strategic_objective:
            self.strategic_objective = []
        self.strategic_objective.append(strategic_objective)
        
class CapabilityList(maec.Entity):
    _namespace = maec.bundle._namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityListType

    capability = maec.TypedField("Capability", Capability, multiple = True)
    capability_reference = maec.TypedField("Capability_Reference", CapabilityReference, multiple = True)

    def __init__(self):
        super(CapabilityList, self).__init__()
        self.capability = []
        self.capability_reference = []
