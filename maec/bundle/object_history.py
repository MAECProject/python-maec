# MAEC Object History Classes

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

class ObjectHistory(object):
    @classmethod
    def build(cls, bundle):
        """Build the Object History for a Bundle"""
        cls.entries = [] # A list of the Objects in the Object History
        # Get the Objects that are not references
        objects = bundle.get_all_non_reference_objects()
        for object in objects:
            object_history_entry = ObjectHistoryEntry(object)
            # Find and set all Actions that operate on the Object
            if bundle.get_all_actions_on_object(object):
                object_history_entry.actions = bundle.get_all_actions_on_object(object)
            # Add the history entry to the list
            cls.entries.append(object_history_entry)

class ObjectHistoryEntry(object):
    def __init__(self, object = None):
        self.object = object
        self.actions = [] # A list of the Actions that operate on the Object
        self.behaviors = [] # A list of Behaviors that make use of the Object (through Actions?)

    def get_action_names(self):
        """Return a list of the Actions that operated on the Object, via their names"""
        return [x.name.value for x in self.actions if x.name]

    def get_action_context(self):
        """Return a list of the Actions that operated on the Object, via their names,
           along with the Association_Type used in the Action.
        """
        context_list = []
        for action in self.actions:
            if action.name:
                action_name = action.name.value
            else:
                action_name = None
            for associated_object in action.associated_objects:
                if associated_object.association_type:
                    association_type = associated_object.association_type.value
                else:
                    association_type = None
                if associated_object.id_ == self.object.id_ or associated_object.idref == self.object.id_:
                    context_list.append((action_name, association_type))
        return context_list