#MAEC Package Class

#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 12/28/2012

import maec_package_1_0 as package_binding

class package:
    def __init__(self, generator, schema_version, package_attributes_dict = None):
        self.generator = generator
        #Create the MAEC Package object
        self.package = package_binding.PackageType(id=self.generator.generate_pkg_id())
        #Set the schema version
        self.package.set_schema_version(schema_version)
        self.package_attributes_dict = package_attributes_dict
        #Create the subject list
        self.subjects = package_binding.MalwareSubjectListType()
        #Create the namespace and schemalocation declarations
        self.namespace_prefixes = {'xmlns:maecPackage' : '"http://maec.mitre.org/XMLSchema/maec-package-1"',
                                   'xmlns:maecBundle' : '"http://maec.mitre.org/XMLSchema/maec-bundle-3"',
                                   'xmlns:cybox' : '"http://cybox.mitre.org/cybox_v1"',
                                   'xmlns:Common' : '"http://cybox.mitre.org/Common_v1"',
                                   'xmlns:mmdef' : '"http://xml/metadataSharing.xsd"',
                                   'xmlns:xsi' : '"http://www.w3.org/2001/XMLSchema-instance"'}
        self.schemalocations = {'http://maec.mitre.org/XMLSchema/maec-package-1' : 'http://maec.mitre.org/language/version3.0/maec-package-schema.xsd',
                                'http://maec.mitre.org/XMLSchema/maec-bundle-3' :  'http://maec.mitre.org/language/version3.0/maec-bundle-schema.xsd',
                                'http://cybox.mitre.org/Common_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_common_types_v1.0.xsd',
                                'http://cybox.mitre.org/cybox_v1' : 'http://cybox.mitre.org/XMLSchema/cybox_core_v1.0.xsd',
                                'http://xml/metadataSharing.xsd' : 'http://grouper.ieee.org/groups/malware/malwg/Schema1.2/metadataSharing.xsd'}

    #Public methods

    #Add a malware subject
    def add_malware_subject(self, malware_subject):
        self.subjects.add_Malware_Subject(malware_subject)
    
    #Set the grouping relationship based on an input dictionary
    def set_grouping_relationship(self, grouping_relationship_attributes):
        for key, value in grouping_relationship_attributes.items():
            pass

    #Add a namespace to the namespaces list
    def add_namespace(self, namespace_prefix, namespace):
        self.namespace_prefixes[namespace_prefix] = '"' + namespace + '"'

    #Add a schemalocation to the schemalocation list
    def add_schemalocation(self, namespace, schemalocation):
        self.schemalocations[namespace] = schemalocation

    #Build the Package from the input dictionary
    def build_from_dictionary(self):
        for key, value in self.package_attributes_dict.items():
            pass

    #Get the package
    def get(self):
        self.__build__()
        return self.package

    #Export the package and its contents to an XML file
    def export_to_file(self, outfilename):
        self.__build__()
        outfile = open(outfilename, 'w')
        self.package.export(outfile, 0, namespacedef_=self.__build_namespaces_schemalocations())

    #Private methods

    #Build the package, adding any list or other items
    def __build__(self):
        if self.subjects.hasContent_():
            self.package.set_Malware_Subjects(self.subjects)

    #Build the namespace/schemalocation declaration string
    def __build_namespaces_schemalocations(self):
        output_string = '\n '
        schemalocs = []
        first_string = True
        for namespace_prefix, namespace in self.namespace_prefixes.items():
            output_string += (namespace_prefix + '=' + namespace + ' \n ')
        output_string += 'xsi:schemaLocation="'
        for namespace, schemalocation in self.schemalocations.items():
            if first_string:
                schemalocs.append(namespace + ' ' + schemalocation)
                first_string = False
            else:
                schemalocs.append(' ' + namespace + ' ' + schemalocation)
        for schemalocation_string in schemalocs:
            if schemalocs.index(schemalocation_string) == (len(schemalocs) - 1):
                output_string += (schemalocation_string + '"\n')
            else:
                output_string += (schemalocation_string + '\n')
        return output_string