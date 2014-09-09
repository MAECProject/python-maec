.. include:: /_includes/wip_prolog.rst

API Documentation
=================

The *python-maec* APIs are the recommended tools for reading, writing, and manipulating STIX XML documents.

.. note::

	The python-maec APIs are currently under development. As such, API coverage of MAEC data constructs is incomplete; please bear with us as we work toward complete coverage. This documentation also serves to outline current API coverage.

**STIX** -- Modules located in the base `maec`_ package

.. _stix: https://github.com/MAECProject/python-maec/tree/master/maec

.. toctree::
	:titlesonly:

	__init__
	
**MAEC Bundle** -- Modules located in the `maec.bundle`_ package

.. _stix.campaign: https://github.com/STIXProject/python-maec/tree/master/stix/campaign

.. toctree::
	:titlesonly:
	:glob:

	bundle/*
	