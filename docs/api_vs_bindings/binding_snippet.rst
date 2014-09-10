.. code-block:: python

  import sys
  # Import the required bindings
  import maec.bindings.maec_bundle as bundle_binding
  import cybox.bindings.cybox_core as cybox_core_binding
  import cybox.bindings.cybox_common as cybox_common_binding
  import cybox.bindings.file_object as file_binding  
   
  # Instantiate the MAEC/CybOX Entities
  b = bundle_binding.BundleType(id="bundle-1")
  a = bundle_binding.MalwareActionType(id="action-1")
  ao = cybox_core_binding.AssociatedObjectType(id="object-1")
  
  # Build the Associated Object for use in the Action
  f = file_binding.FileObjectType()
  f_name = cybox_common_binding.StringObjectPropertyType(valueOf_="badware.exe")
  f.set_File_Name(f_name)
  f_size = cybox_common_binding.UnsignedLongObjectPropertyType(valueOf_="123456")
  f.set_Size_In_Bytes(f_size)
  f.set_xsi_type = "FileObj:FileObjectType"
  ao.set_Properties(f)
  ao_type = cybox_common_binding.ControlledVocabularyStringType(valueOf_="output")
  ao_type.set_xsi_type("maecVocabs:ActionObjectAssociationTypeVocab-1.0")
  ao.set_Association_Type(ao_type)
 
  # Build the Action and add the Associated Object to it
  a_name = cybox_common_binding.ControlledVocabularyStringType(valueOf_="create file")
  a_name.set_xsi_type("maecVocabs:FileActionNameVocab-1.0")
  a.set_Name(a_name)
  as_objects = cybox_core_binding.AssociatedObjectsType()
  as_objects.add_Associated_Object(ao)
  a.set_Associated_Objects(as_objects)

  # Add the Action to the Bundle
  action_list = bundle_binding.ActionListType()
  action_list.add_Action(a)
  b.set_Actions(action_list)
    
  # Output the Bundle to stdout
  b.export(sys.stdout, 0)