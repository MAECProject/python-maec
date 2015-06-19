# MAEC Capability Classes

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
from maec.bundle import BehaviorReference
from cybox.common import VocabString, String


class CapabilityObjectiveReference(maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityObjectiveReferenceType

    objective_idref = fields.TypedField("objective_idref")

    def __init__(self):
        super(CapabilityObjectiveReference, self).__init__()


class CapabilityReference(maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityReferenceType

    capability_idref = fields.TypedField("capability_idref")

    def __init__(self):
        super(CapabilityReference, self).__init__()


class CapabilityObjectiveRelationship(maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityObjectiveRelationshipType

    relationship_type = fields.TypedField("Relationship_Type", VocabString)
    objective_reference = fields.TypedField("Objective_Reference", CapabilityObjectiveReference, multiple=True)

    def __init__(self):
        super(CapabilityObjectiveRelationship, self).__init__()
        self.objective_reference = []


class CapabilityRelationship(maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityRelationshipType

    relationship_type = fields.TypedField("Relationship_Type", VocabString)
    capability_reference = fields.TypedField("Capability_Reference", CapabilityReference, multiple=True)

    def __init__(self):
        super(CapabilityRelationship, self).__init__()
        self.capability_reference = []


class CapabilityProperty(maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityPropertyType

    name = fields.TypedField("Name", VocabString)
    value = fields.TypedField("Value", String)

    def __init__(self):
        super(CapabilityProperty, self).__init__()


class CapabilityObjective(maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityObjectiveType

    id_ = fields.TypedField("id")
    name = fields.TypedField("Name", VocabString)
    description = fields.TypedField("Description")
    property = fields.TypedField("Property", CapabilityProperty, multiple=True)
    behavior_reference = fields.TypedField("Behavior_Reference", BehaviorReference, multiple=True)
    relationship = fields.TypedField("Relationship", CapabilityObjectiveRelationship, multiple=True)

    def __init__(self, id=None):
        super(CapabilityObjective, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="capability_objective")


class Capability(maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityType

    id_ = fields.TypedField("id")
    name = fields.TypedField("name")
    description = fields.TypedField("Description")
    property = fields.TypedField("Property", CapabilityProperty, multiple=True)
    strategic_objective = fields.TypedField("Strategic_Objective", CapabilityObjective, multiple=True)
    tactical_objective = fields.TypedField("Tactical_Objective", CapabilityObjective, multiple=True)
    behavior_reference = fields.TypedField("Behavior_Reference", BehaviorReference, multiple=True)
    relationship = fields.TypedField("Relationship", CapabilityRelationship, multiple=True)

    def __init__(self, id=None, name=None):
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
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.CapabilityListType

    capability = fields.TypedField("Capability", Capability, multiple=True)
    capability_reference = fields.TypedField("Capability_Reference", CapabilityReference, multiple=True)

    def __init__(self):
        super(CapabilityList, self).__init__()
        self.capability = []
        self.capability_reference = []
