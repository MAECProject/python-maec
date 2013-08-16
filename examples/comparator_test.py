from maec.bundle.bundle import Bundle
from maec.bundle.malware_action import MalwareAction
from maec.package.analysis import Analysis
from maec.package.malware_subject import MalwareSubject
from maec.package.package import Package
from maec.id_generator import Generator
from maec.utils import MAECNamespaceParser
from cybox.core.object import Object 
from cybox.core.associated_object import AssociatedObject

generator = Generator('comp')

bundle = Bundle(generator.generate_bundle_id(), False)
package = Package(id=generator.generate_package_id())
subject = MalwareSubject(id=generator.generate_malware_subject_id())

subject_object_dict = {'id' : generator.generate_object_id(), 'properties' : {'xsi:type' : 'FileObjectType', 'name' : 'foobar.exe', 'size_in_bytes' : '35532'}}
subject.set_malware_instance_object_attributes(Object.from_dict(subject_object_dict))

associated_object_dict = {'properties' : {'id' : generator.generate_object_id(), 'xsi:type' : 'FileObjectType', 'file_name' : 'abcd.dll', 'size_in_bytes' : '12346'}, 'association_type' : {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}}
action = MalwareAction.from_dict({'id' : generator.generate_malware_action_id(), 'name' : {'value' : 'create file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}, 'associated_objects' : [associated_object_dict]})
bundle.add_action(action)

associated_object_dict = { 'properties' : {'id' : generator.generate_object_id(), 'xsi:type' : 'FileObjectType', 'file_name' : 'abcd-unique.dll', 'size_in_bytes' : '12346'}, 'association_type' : {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}}
action = MalwareAction.from_dict({'id' : generator.generate_malware_action_id(), 'name' : {'value' : 'create file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}, 'associated_objects' : [associated_object_dict]})
bundle.add_action(action)


#Add the Bundle to the Malware Subject
subject.add_findings_bundle(bundle)
#Add the Malware Subject to the Package
package.add_malware_subject(subject)


bundle2 = Bundle(generator.generate_bundle_id(), False)
associated_object_dict2 = { 'properties' : { 'id': generator.generate_object_id(), 'xsi:type' : 'FileObjectType', 'file_name' : 'abcd.dll', 'size_in_bytes' : '12346'}, 'association_type' : {'value' : 'output', 'xsi:type' : 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'}}
action2 = MalwareAction.from_dict({'id' : generator.generate_malware_action_id(), 'name' : {'value' : 'create file', 'xsi:type' : 'maecVocabs:FileActionNameVocab-1.0'}, 'associated_objects' : [associated_object_dict]})
bundle2.add_action(action)

comparator = Bundle.compare([bundle, bundle2])
print comparator.get_common()
print comparator.get_unique()

