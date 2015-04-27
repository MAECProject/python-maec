# Example 1 - Simple Package Generation Example
# Generates and exports MAEC Package with:
# - A single Malware Subject
# - A single Bundle embedded in the Malware Subject
# - A single Action embedded in the Bundle
# - A single Capability embedded in the Bundle

from cybox.core import AssociatedObjects, AssociatedObject, Object, AssociationType
from cybox.common import Hash, HashList, VocabString
from cybox.objects.file_object import File
from maec.bundle import Bundle, Collections, MalwareAction, Capability
from maec.package import Analysis, MalwareSubject, Package
from cybox.utils import Namespace
import maec.utils

# Instantiate the ID generator class (for automatic ID generation) with our example namespace
NS = Namespace("http://example.com/", "example")
maec.utils.set_id_namespace(NS)
# Instantiate the Bundle, Package, MalwareSubject, and Analysis classes
bundle = Bundle(defined_subject=False)
package = Package()
subject = MalwareSubject()
analysis = Analysis()
# Create the Object for use in the Malware Instance Object Attributes
subject_object = Object()
subject_object.properties = File()
subject_object.properties.name = 'foobar.exe'
subject_object.properties.size_in_bytes = '35532'
subject_object.properties.hashes = HashList()
subject_object.properties.hashes.append(Hash("8743b52063cd84097a65d1633f5c74f5"))
# Set the Malware Instance Object Attributes with an Object constructed from the dictionary
subject.set_malware_instance_object_attributes(subject_object)
# Create the Associated Object Dictionary for use in the Action
associated_object = AssociatedObject()
associated_object.properties = File() 
associated_object.properties.file_name = 'abcd.dll'
associated_object.properties.size_in_bytes = '123456'
associated_object.association_type = VocabString()
associated_object.association_type.value = 'output'
associated_object.association_type.xsi_type = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'
# Create the Action from another dictionary
action = MalwareAction()
action.name = VocabString()
action.name.value = 'create file'
action.name.xsi_type = 'maecVocabs:FileActionNameVocab-1.0'
action.associated_objects = AssociatedObjects()
action.associated_objects.append(associated_object)
# Add the Action to the Bundle
bundle.add_action(action)
# Create the Capability from another dictionary
capability = Capability()
capability.name = 'persistence'
# Add the Capability to the Bundle
bundle.add_capability(capability)
# Add the Bundle to the Malware Subject
subject.add_findings_bundle(bundle)
subject.findings_bundles.bundle = [bundle]
# Add the Malware Subject to the Package
package.add_malware_subject(subject)
# Export the Package Bindings Object to an XML file and use the namespaceparser for writing out the namespace definitions
package.to_xml_file('sample_maec_package.xml', {"http://example.com/":"example"})
print "Wrote to sample_maec_package.xml"
