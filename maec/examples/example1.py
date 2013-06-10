#Simple MAEC 4.0 Example
#Generates and exports MAEC Package with:
##A Single Malware Subject
##A single Bundle embedded in the Malware Subject
##A single Action embedded in the Bundle

from maec.bundle.bundle import Bundle
from maec.bundle.malware_action import MalwareAction
from maec.package.analysis import Analysis
from maec.package.malware_subject import MalwareSubject
from maec.package.package import Package
from maec.id_generator import Generator
from maec.utils import MAECNamespaceParser
from cybox.core.object import Object 
from cybox.core.associated_object import AssociatedObject

#Instantiate the ID generator class (for automatic ID generation) with our example namespace
generator = Generator('example1')
#Instantiate the Bundle, Package, MalwareSubject, and Analysis classes
bundle = Bundle(id=generator.generate_bundle_id(), defined_subject=False)
package = Package(id=generator.generate_package_id())
subject = MalwareSubject(id=generator.generate_malware_subject_id())
analysis = Analysis(id=generator.generate_analysis_id())
#Create the Subject Object Dictionary for use in the Malware Instance Object Attributes
subject_object_dict = {'id' : generator.generate_object_id(), 'properties' : {'xsi:type' : 'FileObjectType', 'name' : 'foobar.exe', 'size_in_bytes' : '35532'}}
#Set the Malware Instance Object Attributes with an Object constructed from the dictionary
subject.set_malware_instance_object_attributes(Object.from_dict(subject_object_dict))
#Create the Associated Object Dictionary for use in the Action
associated_object_dict = {'id' : generator.generate_object_id(), 'properties' : {'xsi:type' : 'FileObjectType', 'file_name' : 'abcd.dll', 'size_in_bytes' : '12346'}, 'association_type' : {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}}
#Create the Action from another dictionary
action = MalwareAction.from_dict({'id' : generator.generate_malware_action_id(), 'name' : {'value' : 'create file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}, 'associated_objects' : [associated_object_dict]})
#Add the Action to the buundle
bundle.add_action(action)
#Add the Bundle to the Malware Subject
subject.add_findings_bundle(bundle)
#Add the Malware Subject to the Package
package.add_malware_subject(subject)
#Export the Package Bindings Object to an XML file and use the namespaceparser for writing out the namespace definitions
package.to_xml_file('example1.xml')