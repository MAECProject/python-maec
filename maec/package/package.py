# MAEC Package Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields

import maec
import maec.bindings.maec_package as package_binding
from maec.package import MalwareSubjectList, GroupingRelationshipList
from . import _namespace

class Package(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.PackageType
    _namespace = _namespace   

    id_ = fields.TypedField('id')
    timestamp = fields.TypedField('timestamp')
    schema_version = fields.TypedField('schema_version')
    malware_subjects = fields.TypedField('Malware_Subjects', MalwareSubjectList)
    grouping_relationships = fields.TypedField('Grouping_Relationships', GroupingRelationshipList)

    def __init__(self, id = None, schema_version = "2.1", timestamp = None):
        super(Package, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="package")
        self.schema_version = schema_version
        self.timestamp = timestamp
        self.malware_subjects = MalwareSubjectList()
        self.__input_namespaces__ = {}
        self.__input_schemalocations__ = {}

    #Public methods
    #Add a malware subject to this Package
    def add_malware_subject(self, malware_subject):
        self.malware_subjects.append(malware_subject)
    
    #Add a grouping relationship
    def add_grouping_relationship(self, grouping_relationship):
        if not self.grouping_relationships:
            self.grouping_relationships = GroupingRelationshipList()
        self.grouping_relationships.append(grouping_relationship)


    # Create new Package from the XML document at the specified path
    @staticmethod
    def from_xml(xml_file):
        '''
        Returns a tuple of (api_object, binding_object).
        Parameters:
        xml_file - either a filename or a stream object
        '''
        from maec.utils.parser import EntityParser

        parser = EntityParser()
        maec_package = parser.parse_xml(xml_file)
        maec_package_obj = maec_package.to_obj()
        
        return (maec_package, maec_package_obj)

    # Transform duplicate objects within this Package into references pointing to a single canonical object
    def deduplicate_malware_subjects(self):
        """DeDuplicate all Malware_Subjects in the Package. For now, only handles Objects in Findings Bundles"""
        for malware_subject in self.malware_subjects:
            malware_subject.deduplicate_bundles()

            

