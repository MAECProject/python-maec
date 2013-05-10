import cybox.utils as utils
import maec.bindings.mmdef_1_2 as mmdef_binding
import maec.bindings.maec_bundle_3_0 as bundle_binding

class AVClassifications(object):
    def __init__(self):
        self.av_classifications = []

    def to_obj(self):
        av_classifications_obj = bundle_binding.AVClassificationsType()
        av_classifications_obj.set_anyAttributes_({'xsi:type' : 'maecBundle:AVClassificationsType'})
        if len(self.av_classifications) > 0:
            for av_classification in self.av_classifications:
                av_classifications_obj.add_AV_Classification(av_classification.to_obj())
        return av_classifications_obj

    def to_list(self):
        pass

    @staticmethod
    def from_list(av_classifications_list):
        if not av_classifications_list:
            return None
        av_classifications_ = AVClassifications()
        av_classifications_.av_classifications = [AVClassification.from_dict(x) for x in av_classifications_list]
        return av_classifications_

    @staticmethod
    def from_obj(av_classifications_obj):
        pass

class AVClassification(object):
    def __init__(self):
        self.id = None
        self.type = None
        self.classificationname = None
        self.companyname = None
        self.category = None
        self.classificationdetails = None

    def to_obj(self):
        classification_obj = mmdef_binding.classificationObject()
        if self.id is not None: classification_obj.set_id(self.id)
        if self.type is not None: classification_obj.set_type(self.type)
        if self.classificationname is not None: classification_obj.set_classificationName(self.classificationname)
        if self.companyname is not None: classification_obj.set_companyName(self.companyname)
        if self.category is not None: classification_obj.set_category(self.category)
        if self.classificationdetails is not None: pass
        return classification_obj

    def to_dict(self):
        pass

    @staticmethod
    def from_dict(classification_dict):
        if not classification_dict:
            return None
        av_classification_ = AVClassification()
        av_classification_.id = classification_dict.get('id')
        av_classification_.type = classification_dict.get('type')
        av_classification_.classificationname = classification_dict.get('classificationname')
        av_classification_.companyname = classification_dict.get('companyname')
        av_classification_.category = classification_dict.get('category')
        #av_classification_.classificationdetails = classification_dict.get('classificationdetails')
        return av_classification_

    @staticmethod
    def from_object(classification_obj):
        pass