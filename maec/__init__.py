# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from __future__ import absolute_import
from mixbox.entities import Entity as cyboxEntity
from mixbox.entities import EntityList
from mixbox.namespaces import ( get_xmlns_string,
    make_namespace_subset_from_uris, get_schemaloc_string, lookup_prefix)
from mixbox.vendor.six import iteritems, string_types

import maec
from maec.utils import flip_dict, EntityParser

from .version import __version__  # noqa


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
            namespace_dict = namespace_dict.copy()

        # Update the namespace dictionary with namespaces found upon import
        input_namespaces = self._ns_to_prefix_input_namespaces()
        namespace_dict.update(input_namespaces)

        # Check whether we're dealing with a filename or file-like Object
        if isinstance(file, string_types):
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
            for key, value in iteritems(custom_header):
                sanitized_key = str(key).replace("-->", "\\-\\->")
                sanitized_value = str(value).replace("-->", "\\-\\->")
                out_file.write(sanitized_key + ": " + sanitized_value + "\n")
            out_file.write("-->\n")
        elif isinstance(custom_header, string_types):
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
            namespaces.add(lookup_prefix('xsi'))
            namespaces.add(lookup_prefix('maecVocabs'))

            ns_set = make_namespace_subset_from_uris(namespaces)
            if additional_ns_dict:
                for ns, prefix in iteritems(additional_ns_dict):
                    ns_set.add_namespace_uri(ns, prefix)
        else:
            return ""

        return ('\n\t' + ns_set.get_xmlns_string(sort=True, delim='\n\t') +
                '\n\t' + ns_set.get_schemaloc_string(sort=True, delim='\n\t'))

    def _get_namespaces(self, recurse=True):
        # Get all _namespaces for parent classes
        nsset = set(x._namespace for x in self.__class__.__mro__
                      if hasattr(x, '_namespace'))

        #In case of recursive relationships, don't process this item twice
        self.touched = True
        if recurse:
            for x in self._get_children():
                if not hasattr(x, 'touched'):
                    nsset.update(x._get_namespaces())
        del self.touched

        # Add any additional namespaces that may be included in the entity
        input_ns = self._ns_to_prefix_input_namespaces()
        for namespace, alias in iteritems(input_ns):
            nsset.update(namespace)

        return nsset


def parse_xml_instance(filename, check_version = True):
    """Parse a MAEC instance and return the correct Binding and API objects
       Returns a dictionary of MAEC Package or Bundle Binding/API Objects"""
    object_dictionary = {}
    entity_parser = EntityParser()

    object_dictionary['binding'] = entity_parser.parse_xml_to_obj(filename, check_version)
    object_dictionary['api'] = entity_parser.parse_xml(filename, check_version)

    return object_dictionary
