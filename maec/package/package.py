#MAEC Package Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 4/10/2013

import maec.bindings.maec_package_1_0 as package_binding

class Package(object):
    def __init__(self, id, generator, schema_version = None, timestamp = None):
        if id is not None:
            self.id = id
        elif generator is not None:
            self.generator = generator;
            self.id = self.generator.generate_package_id()
        else:
            raise Exception("Must specify id or generator for Package constructor")
        self.schema_version = schema_version
        self.timestamp = timestamp
        self.subjects = []
        self.grouping_relationships = []

    #Public methods
    #Add a malware subject
    def add_malware_subject(self, malware_subject):
        self.subjects.append(malware_subject)
    
    #Add a grouping relationship
    def add_grouping_relationship(self, grouping_relationship):
        self.grouping_relationships.append(grouping_relationship)

    def to_obj(self):
        package_obj = package_binding.PackageType(id=self.id)
        if self.schema_version is not None:
            package_obj.set_schema_version(self.schema_version)
        else:
            package_obj.set_schema_version(1.0)
        if self.timestamp is not None: package_obj.set_timestamp(self.timestamp)
        if len(self.subjects) > 0:
            subject_list = package_binding.MalwareSubjectListType()
            for subject in self.subjects:
                subject_list.add_Malware_Subject(subject.to_obj())
            package_obj.set_Malware_Subjects(subject_list)
        if len(self.grouping_relationships) > 0:
            grouping_relationship_list = package_binding.GroupingRelationshipListType()
            for grouping_relationship in self.grouping_relationships:
                grouping_relationship_list.add_Grouping_Relationship(grouping_relationship.to_obj())
            package_obj.set_Grouping_Relationships(grouping_relationship_list)

        return package_obj

    def to_dict(self):
        pass

    #Build the Package from the input dictionary
    @staticmethod
    def from_dict(package_dict):
        for key, value in self.package_dict.items():
            pass

    @staticmethod
    def from_obj(package_obj):
        package_dict = {}
        pass

