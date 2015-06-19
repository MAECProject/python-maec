# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import collections
import inspect
import json
from StringIO import StringIO

from cybox import Entity as cyboxEntity
from cybox import EntityList
from cybox.utils import Namespace, META

import bindings.maec_bundle as bundle_binding
import bindings.maec_package as package_binding
import maec
from maec.utils import flip_dict, maecMETA, EntityParser

from .version import __version__  # noqa


def get_xmlns_string(ns_set):
    """Build a string with 'xmlns' definitions for every namespace in ns_set.

    Arguments:
    - ns_set: a set (or other iterable) of Namespace objects
    """
    xmlns_format = 'xmlns:{0.prefix}="{0.name}"'
    return "\n\t".join([xmlns_format.format(x) for x in ns_set if x])


def get_schemaloc_string(ns_set):
    """Build a "schemaLocation" string for every namespace in ns_set.

    Arguments:
    - ns_set: a set (or other iterable) of Namespace objects
    """
    schemaloc_format = '{0.name} {0.schema_location}'
    # Only include schemas that have a schema_location defined (for instance,
    # 'xsi' does not.
    return " ".join([schemaloc_format.format(x) for x in ns_set
                     if x and x.schema_location])

class Entity(cyboxEntity):
    """Base class for all classes in the MAEC SimpleAPI."""

    def _ns_to_prefix_input_namespaces(self):
        """The namespace that are extracted during parse are mapped from
        namespace prefix to namespace. The serialization code expects a mapping
        from namespace to prefix.

        """
        input_namespaces = getattr(self, '__input_namespaces__', {})
        return flip_dict(input_namespaces)

    def to_xml_file(self, file, namespace_dict=None, custom_header=None):
        """Export an object to an XML file. Only supports Package or Bundle
        objects at the moment.
        
        Args:
            file: the name of a file or a file-like object to write the output to.
            namespace_dict: a dictionary of mappings of additional XML namespaces to
                prefixes.
            custom_header: a string, list, or dictionary that represents a custom
                XML header to be written to the output.

        """
        if not namespace_dict:
            namespace_dict = {}
        else:
            # Make a copy so we don't pollute the source
            namespace_dict = dict(namespace_dict.iteritems())

        # Update the namespace dictionary with namespaces found upon import
        input_namespaces = self._ns_to_prefix_input_namespaces()
        namespace_dict.update(input_namespaces)

        # Check whether we're dealing with a filename or file-like Object
        if isinstance(file, basestring):
            out_file  = open(file, 'w')
        else:
            out_file = file
        out_file.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        # Write out the custom header, if included
        if isinstance(custom_header, list):
            out_file.write("<!--\n")
            for line in custom_header:
                out_file.write(line.replace("-->", "\\-\\->") + "\n")
            out_file.write("-->\n")
        elif isinstance(custom_header, dict):
            out_file.write("<!--\n")
            for key, value in custom_header.iteritems():
                sanitized_key = str(key).replace("-->", "\\-\\->")
                sanitized_value = str(value).replace("-->", "\\-\\->")
                out_file.write(sanitized_key + ": " + sanitized_value + "\n")
            out_file.write("-->\n")
        elif isinstance(custom_header, basestring):
            out_file.write("<!--\n")
            out_file.write(custom_header.replace("-->", "\\-\\->") + "\n")
            out_file.write("-->\n")
        out_file.write(self.to_xml(namespace_dict=namespace_dict))
        out_file.close()

    def _get_namespace_def(self, additional_ns_dict=None):
        # copy necessary namespaces

        namespaces = self._get_namespaces()

        # if there are any other namepaces, include xsi for "schemaLocation"
        # also, include the MAEC default vocabularies schema by default
        if namespaces:
            namespaces.update([maecMETA.lookup_prefix('xsi')])
            namespaces.update([maecMETA.lookup_prefix('maecVocabs')])

        if namespaces and additional_ns_dict:
            namespace_list = [x.name for x in namespaces if x]
            for ns, prefix in additional_ns_dict.iteritems():
                if ns not in namespace_list:
                    namespaces.update([Namespace(ns, prefix)])

        if not namespaces:
            return ""

        namespaces = sorted(namespaces, key=str)

        return ('\n\t' + get_xmlns_string(namespaces) +
                '\n\txsi:schemaLocation="' + get_schemaloc_string(namespaces) +
                '"')

    def _get_namespaces(self, recurse=True):
        nsset = set()

        # Get all _namespaces for parent classes
        namespaces = [x._namespace for x in self.__class__.__mro__
                      if hasattr(x, '_namespace')]

        nsset.update([maecMETA.lookup_namespace(ns) for ns in namespaces])

        #In case of recursive relationships, don't process this item twice
        self.touched = True
        if recurse:
            for x in self._get_children():
                if not hasattr(x, 'touched'):
                    nsset.update(x._get_namespaces())
        del self.touched

        # Add any additional namespaces that may be included in the entity
        input_ns = self._ns_to_prefix_input_namespaces()
        for namespace, alias in input_ns.iteritems():
            maec_ns = maecMETA.lookup_namespace(namespace)
            cybox_ns = META.lookup_namespace(namespace)
            if not maec_ns and not cybox_ns:
                nsset.add(Namespace(namespace, alias))

        return nsset

def parse_xml_instance(filename, check_version = True):
    """Parse a MAEC instance and return the correct Binding and API objects
       Returns a dictionary of MAEC Package or Bundle Binding/API Objects"""
    object_dictionary = {}
    entity_parser = EntityParser()

    object_dictionary['binding'] = entity_parser.parse_xml_to_obj(filename, check_version)
    object_dictionary['api'] = entity_parser.parse_xml(filename, check_version)

    return object_dictionary
