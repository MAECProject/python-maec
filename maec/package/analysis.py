#MAEC Analysis Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 02/14/2013

import maec.bindings.maec_package_1_0 as package_binding
import maec.bindings.maec_bundle_3_0 as bundle_binding
import cybox.utils as utils
from cybox.common.toolinformation import Tool_Information
        
class Analysis(object):
    def __init__(self, generator, method = None, type = None, analysis_attributes_dict = None):
        self.generator = generator
        self.analysis_obj = package_binding.AnalysisType(id=self.generator.generate_ana_id())
        if method is not None:
            self.analysis_obj.set_method(method)
        if type is not None:
            self.analysis_obj.set_type(type)
        self.analysis_attributes_dict = analysis_attributes_dict
        self.tool_list = package_binding.ToolListType()

    #"Public" methods
    def set_findings_bundle_reference(self, bundle_idref):
        bundle_reference = bundle_binding.BundleReferenceType(bundle_idref = bundle_idref)
        self.analysis.set_Findings_Bundle_Reference(bundle_reference)

    def set_summary(self, summary):
        self.analysis.set_Summary(summary)
   
    def add_tool(self, tool_dict):
        tool_obj = Tool_Information.object_from_dict(tool_dict)
        if tool_obj.hasContent_() : self.tool_list.add_Tool(tool_obj)

    def set_type(self, type):
        if utils.test_value(type) : self.analysis_obj.set_type(type)

    def set_method(self, method):
        if utils.test_value(method) : self.analysis_obj.set_method(method)

    #Create and return the Analysis from the input dictionary
    @classmethod
    def object_from_dict(cls, analysis_dict):
        analysis_obj = package_binding.AnalysisType()
        for key, value in analysis_dict.items():
            if key == 'id': analysis_obj.set_id(value)
            elif key == 'type': analysis_obj.set_type(value)
            elif key == 'method' : analysis_obj.set_method(value)
            elif key == 'ordinal_position' : analysis_obj.set_ordinal_position(value)
            elif key == 'start_datetime' : analysis_obj.set_start_datetime(value)
            elif key == 'complete_datetime' : analysis_obj.set_complete_datetime(value)
            elif key == 'lastupdate_datetime' : analysis_obj.set_lastupdate_datetime(value)
            elif key == 'method' : analysis_obj.set_method(value)
            elif key == 'source' : 
                source_dict = value
                source = package_binding.SourceType()
                for source_key, source_value in source_dict.items(): 
                    if source_key == 'name': source.set_Name(source_value)
                    if source_key == 'method': source.set_Method(source_value)
                    if source_key == 'reference': source.set_Reference(source_value)
                    if source_key == 'organization': source.set_Organization(source_value)
                    if source_key == 'url': source.set_URL(source_value)
                if source.hasContent_(): analysis_obj.set_Source(source)
            elif key == 'analysts':
                pass
            elif key == 'summary' : analysis_obj.set_Summary(value)
            elif key == 'comments' :
                comments = value
                comment_list = package_binding.CommentListType()
                for comment_dict in comments:
                    comment = package_binding.CommentType()
                    for comment_key, comment_value in comment_dict.items():
                        if comment_key == 'author' : comment.set_author(comment_value)
                        if comment_key == 'timestamp' : comment.set_timestamp(comment_value)
                        if comment_key == 'value' : comment.set_valueOf_(comment_value)
                    if comment.hasContent_(): comment_list.add_Comment(comment)
                if comment_list.hasContent_(): analysis_obj.set_Comments(comment_list)
            elif key == 'findings_bundle_reference' : 
                findings_bundle_reference = bundle_binding.BundleReferenceType(bundle_idref = value)
                analysis_obj.set_Findings_Bundle_Reference(findings_bundle_reference)
            elif key == 'tools':
                tools = value
                tools_obj = package_binding.ToolListType()
                for tool_dict in tools:
                    tool_obj = Tool_Information.object_from_dict(tool_dict)
                    if tool_obj.hasContent_() : tools_obj.add_Tool(tool_obj)
            return analysis_obj

    def get(self):
        if self.tool_list.hasContent_():
            self.analysis_obj.set_Tools(self.tool_list)
        return self.analysis_obj
    
    #"Private" methods
    
    def __build__(self):
        if self.tool_list.hasContent_():
            self.analysis_obj.set_Tools(tool_list)      
