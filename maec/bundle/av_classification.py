import maec
import maec.bindings.maec_bundle as bundle_binding
from cybox.common import ToolInformation

class AVClassification(ToolInformation):
    def __init__(self, classification = None, tool_name = None, tool_vendor = None):
        super(AVClassification, self).__init__(tool_name, tool_vendor)
        self.engine_version = None
        self.definition_version = None
        self.classification_name = None

    def to_obj(self):
        av_classification_obj = super(AVClassification, self).to_obj(bundle_binding.AVClassificationType())
        if self.engine_version is not None : av_classification_obj.set_Engine_Version(self.engine_version)
        if self.definition_version is not None : av_classification_obj.set_Definition_Version(self.definition_version)
        if self.classification_name is not None : av_classification_obj.set_Classification_Name(self.classification_name)
        return av_classification_obj

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
        av_classification_.engine_version = av_classification_obj.get_Engine_Version()
        av_classification_.definition_version = av_classification_obj.get_Definition_Version()
        av_classification_.classification_name = av_classification_obj.get_Classification_Name()
        return av_classification_

class AVClassifications(maec.EntityList):
    _contained_type = AVClassification
    _binding_class = bundle_binding.AVClassificationsType
    _binding_var = "AV_Classification"
