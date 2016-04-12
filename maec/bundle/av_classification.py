# MAEC AV Classification classes
# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from cybox.common import ToolInformation
from mixbox import fields

import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding


class AVClassification(ToolInformation, maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.AVClassificationType

    def __init__(self, classification=None, tool_name=None, tool_vendor=None):
        super(AVClassification, self).__init__(tool_name=tool_name, tool_vendor=tool_vendor)
        self.engine_version = None
        self.definition_version = None
        self.classification_name = classification

    def to_obj(self, ns_info=None):
        obj = super(AVClassification, self).to_obj(ns_info=ns_info)
        if self.engine_version is not None :
            obj.Engine_Version = self.engine_version
        if self.definition_version is not None : 
            obj.Definition_Version = self.definition_version
        if self.classification_name is not None : 
            obj.Classification_Name = self.classification_name
        return obj

    def to_dict(self):
        d = super(AVClassification, self).to_dict()

        if self.engine_version is not None:
            d['engine_version'] = self.engine_version
        if self.definition_version is not None:
            d['definition_version'] = self.definition_version
        if self.classification_name is not None:
            d['classification_name'] = self.classification_name

        return d

    @classmethod
    def from_dict(cls, cls_dict):
        if not cls_dict:
            return None

        av_classification_ = super(AVClassification, cls).from_dict(cls_dict)
        av_classification_.engine_version = cls_dict.get('engine_version')
        av_classification_.definition_version = cls_dict.get('definition_version')
        av_classification_.classification_name = cls_dict.get('classification_name')
        return av_classification_

    @classmethod
    def from_obj(cls, cls_obj):
        if not cls_obj:
            return None
        av_classification_ = super(AVClassification, cls).from_obj(cls_obj)
        av_classification_.engine_version = cls_obj.Engine_Version
        av_classification_.definition_version = cls_obj.Definition_Version
        av_classification_.classification_name = cls_obj.Classification_Name
        return av_classification_


class AVClassifications(maec.EntityList):
    _binding_class = bundle_binding.AVClassificationsType
    _namespace = _namespace
    av_classification = fields.TypedField("AV_Classification", AVClassification, multiple=True)
