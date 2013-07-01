#MAEC Package Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 5/15/2013

import maec
import datetime
import maec.bindings.maec_package as package_binding
from maec.package.malware_subject import MalwareSubjectList
from maec.package.grouping_relationship import GroupingRelationshipList

class Package(maec.Entity):
    def __init__(self, id, schema_version = 2.0, timestamp = None):
        super(Package, self).__init__()
        self.id = id
        self.schema_version = schema_version
        self.timestamp = timestamp
        self.malware_subjects = MalwareSubjectList()
        self.grouping_relationships = GroupingRelationshipList()

    #Public methods
    #Add a malware subject
    def add_malware_subject(self, malware_subject):
        self.malware_subjects.append(malware_subject)
    
    #Add a grouping relationship
    def add_grouping_relationship(self, grouping_relationship):
        self.grouping_relationships.append(grouping_relationship)

    def to_obj(self):
        package_obj = package_binding.PackageType(id=self.id)
        if self.schema_version is not None: package_obj.set_schema_version(self.schema_version)
        if self.timestamp is not None: package_obj.set_timestamp(self.timestamp.isoformat())
        if len(self.malware_subjects) > 0: package_obj.set_Malware_Subjects(self.malware_subjects.to_obj())
        if len(self.grouping_relationships) > 0: package_obj.set_Grouping_Relationships(self.grouping_relationships.to_obj())
        return package_obj

    def to_dict(self):
        package_dict = {}
        if self.id is not None : package_dict['id'] = self.id
        if self.schema_version is not None: package_dict['schema_version'] = self.schema_version
        if self.timestamp is not None: package_dict['timestamp'] = self.timestamp.isoformat()
        if len(self.malware_subjects) > 0: package_dict['malware_subjects'] = self.malware_subjects.to_list()
        if len(self.grouping_relationships) > 0: package_dict['grouping_relationships'] = self.grouping_relationships.to_list()
        return package_dict

    #Build the Package from the input dictionary
    @staticmethod
    def from_dict(package_dict):
        if not package_dict:
            return None
        package_ = Package(None)
        package_.id = package_dict.get('id')
        package_.schema_version = package_dict.get('schema_version')
        package_.timestamp = datetime.datetime.strptime(package_dict.get('timestamp'), "%Y-%m-%dT%H:%M:%S.%f")
        package_.malware_subjects = MalwareSubjectList.from_list(package_dict.get('malware_subjects', []))
        package_.grouping_relationships = GroupingRelationshipList.from_list(package_dict.get('grouping_relationships', []))
        return package_

    @staticmethod
    def from_obj(package_obj):
        if not package_obj:
            return None
        package_ = Package(None)
        package_.id = package_obj.get_id()
        package_.schema_version = package_obj.get_schema_version()
        package_.timestamp = package_obj.get_timestamp()
        if package_obj.get_Malware_Subjects() is not None : package_.malware_subjects = MalwareSubjectList.from_obj(package_obj.get_Malware_Subjects())
        if package_obj.get_Grouping_Relationships() is not None : package_.grouping_relationships = GroupingRelationshipList.from_obj(package_obj.get_Grouping_Relationships())
        return package_
        
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
            

