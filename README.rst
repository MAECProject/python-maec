python-maec
===========

A Python library for parsing, manipulating, and generating MAEC content.

:Source: https://github.com/MAECProject/python-maec
:Documentation: http://maec.readthedocs.org
:Information: http://maec.mitre.org
:Download: https://pypi.python.org/pypi/maec/

|travis badge| |landscape.io badge| |version badge| |downloads badge|

.. |travis badge| image:: https://api.travis-ci.org/MAECProject/python-maec.png?branch=master
   :target: https://travis-ci.org/MAECProject/python-maec
   :alt: Build Status
.. |landscape.io badge| image:: https://landscape.io/github/MAECProject/python-maec/master/landscape.png
   :target: https://landscape.io/github/MAECProject/python-maec/master
   :alt: Code Health
.. |version badge| image:: https://pypip.in/v/maec/badge.png
   :target: https://pypi.python.org/pypi/maec/
.. |downloads badge| image:: https://pypip.in/d/maec/badge.png
   :target: https://pypi.python.org/pypi/maec/


Overview
--------

A primary goal of the python-maec library is to remain faithful to both the
MAEC standard and to customary Python practices. There are places where these
will conflict, and the goal is to make the library intuitive both to those
familiar with the XML schemas (but less familiar with Python) and also to
experienced Python developers who want to add MAEC support to their programs.

There are currently two levels of APIs for dealing with MAEC content:

- A low-level API is provided by auto-generated XML Schema - Python class
  bindings. These bindings were generated using `generateDS
  <http://www.rexx.com/~dkuhlman/generateDS.html>`_. With these, any MAEC
  content can be parsed from or written to XML, but requires a bit more
  knowledge of the actual MAEC schemas. These "binding classes" are all located
  in the ``maec.bindings`` package.
- A higher-level API consisting of manually designed Python classes.  These
  "native classes" are intended to behave more like Python programmers would
  expect. As they are designed manually, they currently do not support the
  entire MAEC standard, but rather those object types we expect are used most
  frequently. These "native classes" also support exporting their content as
  Python dictionaries and lists, which can easily be converted to JSON.
  Importing from JSON is also supported.

Compatibility
-------------
The python-maec library is tested and written against python ``2.7.x``. Compatibility with other python versions is neither guaranteed nor implied.

Versioning
----------

Releases of the python-maec library will be given version numbers of the form
``major.minor.update.revision``, where ``major``, ``minor``, and ``update``
correspond to the MAEC version being supported. The ``revision`` number is used
to indicate new versions of the python-maec library itself.

Installation
------------

The ``maec`` package depends on the following Python libraries: 

* ``lxml``

* ``python-cybox``

* ``setuptools`` (only if installing using setup.py)

For Windows installers of the above libraries, we recommend looking here:
http://www.lfd.uci.edu/~gohlke/pythonlibs. python-cybox can be found at
https://github.com/CybOXProject/python-cybox/releases.

To build ``lxml`` on Ubuntu, you will need the following packages from the
Ubuntu package repository:

* python-dev

* libxml2-dev

* libxslt1-dev

* zlib1g-dev

For more information about installing lxml, see
http://lxml.de/installation.html

Feedback
--------

Bug reports and feature requests are welcome and encouraged. Pull requests are
especially appreciated. Feel free to use the issue tracker on GitHub or send an
email directly to maec@mitre.org.
