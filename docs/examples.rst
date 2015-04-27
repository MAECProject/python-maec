.. _examples:

Examples
========

This page includes some basic examples of creating and parsing MAEC content.

There are a couple things we do in these examples for purposes of demonstration
that shouldn't be done in production code:

* When calling ``to_xml()``, we use ``include_namespaces=False``. This is to
  make the example output easier to read, but means the resulting output
  cannot be successfully parsed. The XML parser doesn't know what namespaces
  to use if they aren't included. In production code, you should explicitly
  set ``include_namespaces`` to ``True`` or omit it entirely (``True`` is the
  default).

* We use ``set_id_method(IDGenerator.METHOD_INT)`` to make IDs for Malware 
  Subjects and Actions easier to read and cross-reference within the XML 
  document. In production code, you should omit this statement, which causes 
  random UUIDs to be created instead, or create explicit IDs yourself for 
  Malware Subjects and Actions.

Creating Packages
-----------------

The most commonly used MAEC output format is the MAEC Package, which can contain
one or more Malware Subjects. Malware Subjects (discussed in more detail below) 
encompass all of the data for a single malware instance, including that from 
different types of analysis.


.. testcode::

    from maec.package import Package, MalwareSubject
    from maec.utils import IDGenerator, set_id_method

    set_id_method(IDGenerator.METHOD_INT)
    p = Package()
    ms = MalwareSubject()
    p.add_malware_subject(ms)

    print p.to_xml(include_namespaces=False)

Which outputs:

.. testoutput::

    <maecPackage:MAEC_Package id="example:package-1" schema_version="2.1">
        <maecPackage:Malware_Subjects>
            <maecPackage:Malware_Subject id="example:malware_subject-2">
            </maecPackage:Malware_Subject>
        </maecPackage:Malware_Subjects>
    </maecPackage:MAEC_Package>

Creating Malware Subjects
-------------------------

The easiest way to create a Malware Subject is to construct one and then set 
various properties on it.  The Malware_Instance_Object_Attributes field on a 
Malware Subject MUST be set in order to identify the particular malware instance
that it is characterizing.


.. testcode::

    from maec.package import MalwareSubject
    from maec.utils import IDGenerator, set_id_method
    from cybox.core import Object
    from cybox.objects.file_object import File

    set_id_method(IDGenerator.METHOD_INT)
    ms = MalwareSubject()
    ms.malware_instance_object_attributes = Object()
    ms.malware_instance_object_attributes.properties = File()
    ms.malware_instance_object_attributes.properties.file_name = "malware.exe"
    ms.malware_instance_object_attributes.properties.file_path = "C:\Windows\Temp\malware.exe"
    print ms.to_xml(include_namespaces=False)

Which outputs:

.. testoutput::

    <maecPackage:MalwareSubjectType id="example:malware_subject-1">
        <maecPackage:Malware_Instance_Object_Attributes id="example:Object-1">
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:File_Name>malware.exe</FileObj:File_Name>
                <FileObj:File_Path>C:\Windows\Temp\malware.exe</FileObj:File_Path>
            </cybox:Properties>
        </maecPackage:Malware_Instance_Object_Attributes>
    </maecPackage:MalwareSubjectType>

Creating Bundles
----------------

In MAEC, the ``Bundle`` represents a container for capturing the results from a
particular malware analysis that was performed on a malware instance. While a
``Bundle`` is most commonly included as part of a Malware Subject, it can also
be used a standalone output format when only malware analysis results for a 
malware instance wish to be shared. We'll cover both cases here.

Creating Standalone Bundles
---------------------------

Standalone Bundles function very similarly to Malware Subjects. Therefore, the 
easiest way to create a standalone Bundle is to construct one and then set 
various properties on it.  The Malware_Instance_Object_Attributes field on a 
standalone Bundle MUST be set in order to identify the particular malware 
instance that it is characterizing.

.. testcode::

    from maec.bundle import Bundle
    from maec.utils import IDGenerator, set_id_method
    from cybox.core import Object
    from cybox.objects.file_object import File

    set_id_method(IDGenerator.METHOD_INT)
    b = Bundle()
    b.malware_instance_object_attributes = Object()
    b.malware_instance_object_attributes.properties = File()
    b.malware_instance_object_attributes.properties.file_name = "malware.exe"
    b.malware_instance_object_attributes.properties.file_path = "C:\Windows\Temp\malware.exe"

    print b.to_xml(include_namespaces=False)

Which outputs:

.. testoutput::

    <maecBundle:MAEC_Bundle defined_subject="false" id="example:bundle-1" schema_version="4.1">
        <maecBundle:Malware_Instance_Object_Attributes id="example:Object-1">
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:File_Name>malware.exe</FileObj:File_Name>
                <FileObj:File_Path>C:\Windows\Temp\malware.exe</FileObj:File_Path>
            </cybox:Properties>
        </maecBundle:Malware_Instance_Object_Attributes>
    </maecBundle:MAEC_Bundle>

Creating and adding Bundles to a Malware Subject
------------------------------------------------

Bundles in a Malware Subject are defined nearly identically to those of the 
standalone variety, with the sole exception that they do not require their
Malware_Instance_Object_Attributes field to be set, since this would already
be defined in their parent Malware Subject.

.. testcode::

    from maec.package import MalwareSubject
    from maec.bundle import Bundle
    from maec.utils import IDGenerator, set_id_method
    from cybox.core import Object
    from cybox.objects.file_object import File

    set_id_method(IDGenerator.METHOD_INT)
    ms = MalwareSubject()
    ms.malware_instance_object_attributes = Object()
    ms.malware_instance_object_attributes.properties = File()
    ms.malware_instance_object_attributes.properties.file_name = "malware.exe"
    ms.malware_instance_object_attributes.properties.file_path = "C:\Windows\Temp\malware.exe"

    b = Bundle()
    ms.add_findings_bundle(b)

    print ms.to_xml(include_namespaces=False)

Which outputs:

.. testoutput::

    <maecPackage:MalwareSubjectType id="example:malware_subject-1">
        <maecPackage:Malware_Instance_Object_Attributes id="example:Object-1">
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:File_Name>malware.exe</FileObj:File_Name>
                <FileObj:File_Path>C:\Windows\Temp\malware.exe</FileObj:File_Path>
            </cybox:Properties>
        </maecPackage:Malware_Instance_Object_Attributes>
        <maecPackage:Findings_Bundles>
            <maecPackage:Bundle defined_subject="false" id="example:bundle-2" schema_version="4.1"/>
        </maecPackage:Findings_Bundles>
    </maecPackage:MalwareSubjectType>


Creating and adding Actions to a Bundle
---------------------------------------

MAEC uses its ``MalwareAction`` to capture the low-level dynamic entities, such
as API calls or their abstractions, performed by malware. A ``MalwareAction`` is
stored in a Bundle (either standalone or embedded in a Malware Subject, as 
discussed above). As with the other MAEC entities, the easiest way to use the 
``MalwareAction`` is to instantiate it and then set various properties on it as 
needed.

.. testcode::

    from maec.bundle import Bundle
    from maec.bundle import MalwareAction
    from maec.utils import IDGenerator, set_id_method
    from cybox.core import Object, AssociatedObjects, AssociatedObject
    from cybox.objects.file_object import File
    from cybox.common import VocabString

    set_id_method(IDGenerator.METHOD_INT)
    b = Bundle()
    a = MalwareAction()
    ao = AssociatedObject()

    ao.properties = File()
    ao.properties.file_name = "badware.exe"
    ao.properties.size_in_bytes = "123456"
    ao.association_type = VocabString()
    ao.association_type.value = 'output'
    ao.association_type.xsi_type = 'maecVocabs:ActionObjectAssociationTypeVocab-1.0'

    a.name = VocabString()
    a.name.value = 'create file'
    a.name.xsi_type = 'maecVocabs:FileActionNameVocab-1.0'
    a.associated_objects = AssociatedObjects()
    a.associated_objects.append(ao)

    b.add_action(a)

    print b.to_xml(include_namespaces = False)

.. testoutput::

    <maecBundle:MAEC_Bundle defined_subject="false" id="example:bundle-1" schema_version="4.1">
        <maecBundle:Actions>
            <maecBundle:Action id="example:action-2">
                <cybox:Name xsi:type="maecVocabs:FileActionNameVocab-1.0">create file</cybox:Name>
                <cybox:Associated_Objects>
                    <cybox:Associated_Object id="example:Object-1">
                        <cybox:Properties xsi:type="FileObj:FileObjectType">
                            <FileObj:File_Name>badware.exe</FileObj:File_Name>
                            <FileObj:Size_In_Bytes>123456</FileObj:Size_In_Bytes>
                        </cybox:Properties>
                        <cybox:Association_Type xsi:type="maecVocabs:ActionObjectAssociationTypeVocab-1.0">output</cybox:Association_Type>
                    </cybox:Associated_Object>
                </cybox:Associated_Objects>
            </maecBundle:Action>
        </maecBundle:Actions>
    </maecBundle:MAEC_Bundle>
