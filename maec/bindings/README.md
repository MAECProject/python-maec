MAEC Python Bindings
--------------------------------
These are the latest Python bindings for MAEC v4.1. The required CybOX Bindings can be found at: https://github.com/CybOXProject/Tools/tree/master/Bindings/Python 

-maec_bundle: the MAEC Bundle v4.1 schema bindings. 

-maec_package: the MAEC Package v2.1 schema bindings. 

-maec_container: the MAEC Container v2.1 schema bindings.  

-mmdef_1_2: the Malware Metadata Exchange Format (MMDEF) v1.2 bindings, imported
and used by the MAEC Package.

Dependencies
------------
For parsing of MAEC instances (using the parse() method),
these bindings require version 2.3+ of the Python lxml module to be installed. 

Please see:
http://lxml.de/installation.html
or
http://pypi.python.org/pypi/lxml/2.3 (for Windows)

