.. include:: /_includes/wip_prolog.rst

API Documentation
=================

The *python-maec* APIs are the recommended tools for reading, writing, and manipulating MAEC XML documents.

.. note::

	The python-maec APIs are currently under development. As such, API coverage of MAEC data constructs is incomplete; please bear with us as we work toward complete coverage. This documentation also serves to outline current API coverage.

**STIX** -- Modules located in the base `maec`_ package

.. _maec: https://github.com/MAECProject/python-maec/tree/master/maec

.. toctree::
	:titlesonly:

	__init__
	
**MAEC Bundle** -- Modules located in the `maec.bundle`_ package

.. _maec.bundle: https://github.com/MAECProject/python-maec/tree/master/bundle/bundle

.. toctree::
	:titlesonly:
	:glob:

	bundle/*
	