# MAEC AV Classification classes

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved


import maec
from . import _namespace
import maec.bindings.maec_bundle as bundle_binding
from cybox.common import ToolInformation

class AVClassification(ToolInformation, maec.Entity):
    _namespace = _namespace
    _binding = bundle_binding
    _binding_class = bundle_binding.AVClassificationType

    def __init__(self, classification = None, tool_name = None, tool_vendor = None):
        super(AVClassification, self).__init__(tool_name, tool_vendor)
        self.engine_version = None
        self.definition_version = None
        self.classification_name = classification

    def to_obj(self, return_obj=None, ns_info=None):
        if not return_obj:
            return_obj = self._binding_class()

        super(AVClassification, self).to_obj(return_obj=return_obj, ns_info=ns_info)

        if self.engine_version is not None :
            return_obj.Engine_Version = self.engine_version
        if self.definition_version is not None : 
            return_obj.Definition_Version = self.definition_version
        if self.classification_name is not None : 
            return_obj.Classification_Name = self.classification_name
        return return_obj

    def to_dict(self):
        av_classification_dict = super(AVClassification, self).to_dict()
        if self.engine_version is not None : av_classification_dict['engine_version'] = self.engine_version
        if self.definition_version is not None : av_classification_dict['definition_version'] = self.definition_version
        if self.classification_name is not None : av_classification_dict['classification_name'] = self.classification_name
        return av_classification_dict

    @staticmethod
    def from_dict(av_classification_dict):
        if not av_classification_dict:
            return None
        av_classification_ = ToolInformation.from_dict(av_classification_dict, AVClassification())
        av_classification_.engine_version = av_classification_dict.get('engine_version')
        av_classification_.definition_version = av_classification_dict.get('definition_version')
        av_classification_.classification_name = av_classification_dict.get('classification_name')
        return av_classification_

    @staticmethod
    def from_obj(av_classification_obj):
        if not av_classification_obj:
            return None
        av_classification_ = ToolInformation.from_obj(av_classification_obj, AVClassification())
        av_classification_.engine_version = av_classification_obj.Engine_Version
        av_classification_.definition_version = av_classification_obj.Definition_Version
        av_classification_.classification_name = av_classification_obj.Classification_Name
        return av_classification_

class AVClassifications(maec.EntityList):
    _contained_type = AVClassification
    _binding_class = bundle_binding.AVClassificationsType
    _binding_var = "AV_Classification"
    _namespace = _namespace
