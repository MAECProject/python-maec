__version__ = "4.0.0a2"

import collections
import json
from StringIO import StringIO
from maec.utils.nsparser import MAECNamespaceParser

class Entity(object):
    """Base class for all classes in the MAEC SimpleAPI."""

    def to_xml(self):
        """Export an object as an XML String"""

        s = StringIO()
        self.to_obj().export(s, 0)
        return s.getvalue()
        
    def to_xml_file(self, filename):
        """Export an object to an XML file. Only supports Package or Bundle objects at the moment."""
  
        out_file  = open(filename, 'w')
        out_file.write("<?xml version='1.0' encoding='UTF-8'?>\n")
        out_file.write("<!DOCTYPE doc [<!ENTITY comma '&#44;'>]>\n")
        self.to_obj().export(out_file, 0, namespacedef_=MAECNamespaceParser(self.to_obj()).get_namespace_schemalocation_str())
        out_file.close()

    def to_json(self):
        return json.dumps(self.to_dict())


class EntityList(collections.MutableSequence, Entity):
    _contained_type = object

    def __init__(self):
        self._inner = []

    def __getitem__(self, key):
        return self._inner.__getitem__(key)

    def __setitem__(self, key, value):
        if not self._is_valid(value):
            value = self._try_fix_value(value)
        self._inner.__setitem__(key, value)

    def __delitem__(self, key):
        self._inner.__delitem__(key)

    def __len__(self):
        return len(self._inner)

    def insert(self, idx, value):
        if not self._is_valid(value):
            value = self._try_fix_value(value)
        self._inner.insert(idx, value)

    def _is_valid(self, value):
        """Check if this is a valid object to add to the list.

        If the function is not overridden, only objects of type
        _contained_type can be added.
        """
        return isinstance(value, self._contained_type)

    def _try_fix_value(self, value):
        new_value = self._fix_value(value)
        if not new_value:
            raise ValueError("Can't put '%s' (%s) into a %s" %
                (value, type(value), self.__class__))
        return new_value

    def _fix_value(self, value):
        """Attempt to coerce value into the correct type.

        Subclasses should define this function.
        """
        pass

    @staticmethod
    def _set_list(binding_object, list_):
        """Call the proper method on the binding object to set its value.

        In general, these should be of the form:
            binding_object.set_<something>(list_)

        Since <something> differs fromt class to class, this cannot be done
        generically.
        """
        raise NotImplementedError

    @staticmethod
    def _get_list(binding_object):
        """Call the proper method on the binding object to get its value.

        In general, these should be of the form:
            return binding_object.get_<something>()

        Since <something> differs fromt class to class, this cannot be done
        generically.
        """
        raise NotImplementedError

    # The next four functions can be overridden, but otherwise define the
    # default behavior, for EntityList subclasses which define _contained_type,
    # _binding_class, _get_list, and _set_list

    def to_obj(self, object_type=None):
        tmp_list = [x.to_obj() for x in self]

        if not object_type:
            list_obj = self._binding_class()
        else:
            list_obj = object_type
        self._set_list(list_obj, tmp_list)

        if len(tmp_list) > 0:
            return list_obj
        else:
            return None

    def to_list(self):
        return [h.to_dict() for h in self]

    @classmethod
    def from_obj(cls, list_obj, list_class=None):
        if not list_obj:
            return None

        if not list_class:
            list_ = cls()
        else:
            list_ = list_class

        for item in cls._get_list(list_obj):
            list_.append(cls._contained_type.from_obj(item))

        return list_

    @classmethod
    def from_list(cls, list_list, list_class=None):
        if not isinstance(list_list, list):
            return None

        if not list_class:
            list_ = cls()
        else:
            return None

        for item in list_list:
            list_.append(cls._contained_type.from_dict(item))

        return list_
