#MAEC ID Generator Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 8/23/2013
        
class Generator(object):
    def __init__(self, namespace = None):
        self.namespace = namespace
        self.con_id_base = 0
        self.pkg_id_base = 0
        self.sub_id_base = 0
        self.bnd_id_base = 0
        self.act_id_base = 0
        self.bhv_id_base = 0
        self.obj_id_base = 0
        self.ana_id_base = 0
        self.tol_id_base = 0
        self.imp_id_base = 0
        self.ind_id_base = 0
        self.actc_id_base = 0
        self.bhvc_id_base = 0
        self.objc_id_base = 0
        self.indc_id_base = 0
        self.avclass_id_base = 0
        self.pro_id_base = 0

    def set_namespace(self, namespace):
        self.namespace = namespace

    def get_namespace(self):
        return self.namespace

    def generate_container_id(self):
        self.con_id_base += 1
        return 'maec-' + self.namespace + '-con-' + str(self.con_id_base)

    def generate_package_id(self):
        self.pkg_id_base += 1
        return 'maec-' + self.namespace + '-pkg-' + str(self.pkg_id_base)

    def generate_malware_subject_id(self):
        self.sub_id_base += 1
        return 'maec-' + self.namespace + '-sub-' + str(self.sub_id_base)
    
    def generate_bundle_id(self):
        self.bnd_id_base += 1
        return 'maec-' + self.namespace + '-bnd-' + str(self.bnd_id_base)
    
    def generate_malware_action_id(self):
        self.act_id_base += 1
        return 'maec-' + self.namespace + '-act-' + str(self.act_id_base)
    
    def generate_behavior_id(self):
        self.bhv_id_base += 1
        return 'maec-' + self.namespace + '-bhv-' + str(self.bhv_id_base)
    
    def generate_object_id(self):
        self.obj_id_base += 1
        return 'maec-' + self.namespace + '-obj-' + str(self.obj_id_base)
    
    def generate_analysis_id(self):
        self.ana_id_base += 1
        return 'maec-' + self.namespace + '-ana-' + str(self.ana_id_base)
    
    def generate_tool_id(self):
        self.tol_id_base += 1
        return 'maec-' + self.namespace + '-tol-' + str(self.tol_id_base)

    def generate_candidate_indicator_id(self):
        self.ind_id_base += 1
        return 'maec-' + self.namespace + '-ind-' + str(self.ind_id_base)
        
    def generate_action_implementation_id(self):
        self.imp_id_base += 1
        return 'maec-' + self.namespace + '-imp-' + str(self.imp_id_base)
        
    def generate_action_collection_id(self):
        self.actc_id_base += 1
        return 'maec-' + self.namespace + '-actc-' + str(self.actc_id_base)

    def generate_behavior_collection_id(self):
        self.bhvc_id_base += 1
        return 'maec-' + self.namespace + '-bhvc-' + str(self.bhvc_id_base)

    def generate_object_collection_id(self):
        self.objc_id_base += 1
        return 'maec-' + self.namespace + '-objc-' + str(self.objc_id_base)

    def generate_indicator_collection_id(self):
        self.indc_id_base += 1
        return 'maec-' + self.namespace + '-indc-' + str(self.indc_id_base)

    def generate_avclass_id(self):
        self.avclass_id_base += 1
        return 'mmdef-class-' + str(self.avclass_id_base)

    def generate_process_tree_node_id(self):
        self.pro_id_base += 1
        return 'maec-' + self.namespace + '-pro-' + str(self.pro_id_base)
    
    

