__version__ = "4.1.0.7"

import collections
import json
import inspect
import maec
from StringIO import StringIO
import bindings.maec_bundle as bundle_binding
import bindings.maec_package as package_binding
from cybox import Entity as cyboxEntity
from cybox import EntityList
from cybox import TypedField
from cybox.utils import Namespace
from maec.utils import maecMETA, EntityParser

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

    def to_xml_file(self, filename, namespace_dict=None, custom_header=None):
        """Export an object to an XML file. Only supports Package or Bundle objects at the moment."""
        # Update the namespace dictionary with namespaces found upon import
        if namespace_dict and hasattr(self, '__input_namespaces__'):
            namespace_dict.update(self.__input_namespaces__)
        elif not namespace_dict and hasattr(self, '__input_namespaces__'):
            namespace_dict = self.__input_namespaces__
        out_file  = open(filename, 'w')
        if custom_header:
            for line in custom_header:
                out_file.write[custom_header]
        else:
            out_file.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        self.to_obj().export(out_file.write, 0, namespacedef_ = self._get_namespace_def(namespace_dict))
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

        return nsset

    def _get_children(self):
        #TODO: eventually everything should be in _fields, not the top level
        # of vars()
        for k, v in vars(self).items() + self._fields.items():
            if isinstance(v, Entity) or isinstance(v, cyboxEntity):
                yield v
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, Entity) or isinstance(item, cyboxEntity):
                        yield item


def parse_xml_instance(filename, check_version = True):
    """Parse a MAEC instance and return the correct Binding and API objects
       Returns a dictionary of MAEC Package or Bundle Binding/API Objects"""
    object_dictionary = {}
    entity_parser = EntityParser()

    object_dictionary['binding'] = entity_parser.parse_xml_to_obj(filename, check_version)
    object_dictionary['api'] = entity_parser.parse_xml(filename, check_version)

    return object_dictionary
