#MAEC Package Class

#Copyright (c) 2014, The MITRE Corporation
#All rights reserved

#Compatible with MAEC v4.1
#Last updated 08/20/2014

import maec
import maec.bindings.maec_package as package_binding
from maec.package.malware_subject import MalwareSubjectList
from maec.package.grouping_relationship import GroupingRelationshipList
from cybox.common import DateTime

class Package(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.PackageType
    _namespace = maec.package._namespace   

    id_ = maec.TypedField('id')
    timestamp = maec.TypedField('timestamp')
    schema_version = maec.TypedField('schema_version')
    malware_subjects = maec.TypedField('Malware_Subjects', MalwareSubjectList)
    grouping_relationships = maec.TypedField('Grouping_Relationships', GroupingRelationshipList)

    def __init__(self, id = None, schema_version = "2.1", timestamp = None):
        super(Package, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="package")
        self.schema_version = schema_version
        self.timestamp = timestamp
        self.malware_subjects = MalwareSubjectList()

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
        
        if isinstance(xml_file, basestring):
            f = open(xml_file, "rb")
        else:
            f = xml_file
        
        doc = package_binding.parsexml_(f)
        maec_package_obj = package_binding.PackageType().factory()
        maec_package_obj.build(doc.getroot())
        maec_package = Package.from_obj(maec_package_obj)
        
        return (maec_package, maec_package_obj)

    # Transform duplicate objects within this Package into references pointing to a single canonical object
    def deduplicate_malware_subjects(self):
        """DeDuplicate all Malware_Subjects in the Package. For now, only handles Objects in Findings Bundles"""
        for malware_subject in self.malware_subjects:
            malware_subject.deduplicate_bundles()

            

