Getting Started with python-maec
=================================

.. note::

    The python-maec library is intended for developers who want to add MAEC
    support to existing programs or create new programs that handle MAEC
    content.  Experience with Python development is assumed.

    Other users should look at existing tools_ that support MAEC.

    Understanding XML, XML Schema, and the MAEC language is also
    incredibly helpful when using python-maec in an application.

.. _tools: https://cyboxproject.github.io/#convert

First, you should follow the :ref:`installation` procedures.

Your First MAEC Application
---------------------------

Once you have installed python-maec, you can begin writing Python applications that consume or create STIX content!

.. note::

	The *python-maec* library provides **bindings** and **APIs**, both of which can be used to parse and write MAEC XML files. For in-depth description of the *APIs, bindings, and the differences between the two*, please refer to :doc:`api_vs_bindings/index`

Creating a MAEC Package
***********************

.. code-block:: python
	
  from maec.package.package import Package                # Import the MAEC Package API
  from maec.package.malware_subject import MalwareSubject # Import the MAEC Malware Subject API

  package = STIXPackage()                         # Create an instance of Package
  malware_subject = MalwareSubject()              # Create an instance of MalwareSubject
  package.add_malware_subject(malware_subject)    # Add the Malware Subject to the Package

  print(stix_package.to_xml())                    # Print the XML for this MAEC Package
	
Parsing MAEC XML
****************

.. code-block:: python

  import maec                                # Import the python-maec API

  fn = 'stix_content.xml'                    # The MAEC content filename
  maec_objects = maec.parse_xml_instance(fn) # Parse using the from_xml() method
  api_object = maec_objects['api']           # Get the API object from the parsed objects
  
Example Scripts
---------------

The python-maec repository contains several `example scripts`_ that help
illustrate the capabilities of the APIs. These scripts are simple command line
utilities that can be executed by passing the name of the script to a Python
interpreter.

.. code-block:: bash

    $ python package_generation_example.py

.. _example scripts: https://github.com/MAECProject/python-maec/tree/master/examples


Writing Your Own Application
----------------------------

See the :ref:`examples` page for more examples of using python-maec in your
own application.
