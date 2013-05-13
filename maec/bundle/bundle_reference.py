#MAEC Bundle Reference Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/10/2013

import maec
import maec.bindings.maec_bundle as bundle_binding
       
class BundleReference(maec.Entity):
    def init(self, bundle_idref = None):
        super(BundleReference, self).__init__()
        self.bundle_idref = bundle_idref

    def to_obj(self):
        bundle_reference_obj = bundle_binding.BundleReferenceType()
        if self.bundle_idref is not None : bundle_reference_obj.set_bundle_idref(self.bundle_idref)
        return bundle_reference_obj

    def to_dict(self):
        bundle_reference_dict = {}
        if self.bundle_idref is not None : bundle_reference_dict['bundle_idref'] = self.bundle_idref
        return bundle_reference_dict

    @staticmethod
    def from_dict(bundle_reference_dict):
        if not bundle_reference_dict:
            return None
        bundle_reference_ = BundleReference()
        bundle_reference_.bundle_idref = bundle_reference_dict.get('bundle_idref')
        return bundle_reference_

    @staticmethod
    def from_obj(bundle_reference_obj):
        if not bundle_reference_obj:
            return None
        bundle_reference_ = BundleReference()
        bundle_reference_.bundle_idref = bundle_reference_obj.get_bundle_idref()
        return bundle_reference_
        