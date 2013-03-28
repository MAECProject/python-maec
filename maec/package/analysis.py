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
        if id is not None:
            self.id = id
        elif generator is not None:
            self.generator = generator;
            self.id = self.generator.generate_analysis_id()
        else:
            raise Exception("Must specify id or generator for Analysis constructor")
        
        if method is not None:
            self.method = method
        if type is not None:
            self.type = type
        self.analysis_attributes_dict = analysis_attributes_dict
        self.tool_list = []

    #"Public" methods
    def set_findings_bundle_reference(self, bundle_idref):
        self.bundle_id_ref = bundle_idref

    def set_summary(self, summary):
        self.analysis.set_Summary(summary)
   
    def add_tool(self, tool_dict):
        self.tool_list.push(tool_dict)

    def set_type(self, type):
        self.type = type

    def set_method(self, method):
        self.analysis_obj.set_method(method)

    def set_complete_datetime(self, complete_datetime):
        self.complete_datetime = complete_datetime

    def set_command_line(self, command_line):
        self.command_line = command_line

    def set_analysis_duration(self, analysis_duration):
        self.analysis_duration = analysis_duration

    def set_exit_code(self, exit_code):
        self.exit_code = exit_code

    #return a bindings object
    def to_obj(self):
        analysis_obj = package_binding.AnalysisType(id=self.id)
        if utils.test_value(self.method): analysis_obj.set_method(self.method)
        if utils.test_value(self.type): analysis_obj.set_type(self.type)
        if utils.test_value(self.complete_datetime): self.analysis_obj.set_complete_datetime(self.complete_datetime)
            
        bundle_reference = bundle_binding.BundleReferenceType(bundle_idref = self.bundle_idref)
        analysis_obj.set_Findings_Bundle_Reference(bundle_reference)
            
        tool_list_obj = package_binding.ToolListType()
        for tool_dict in self.tool_list:
            tool_obj = Tool_Information.object_from_dict(tool_dict)
            if tool_obj.hasContent_(): tool_list_obj.add_Tool(tool_obj)
        analysis_obj.set_Tools(tool_list_obj)
        
        dynamic_analysis_metadata_obj = package_binding.DynamicAnalysisMetadataType()
        if utils.test_value(self.command_line): dynamic_analysis_metadata_obj.set_Command_Line(self.command_line)
        if utils.test_value(self.analysis_duration): dynamic_analysis_metadata_obj.set_Analysis_Duration(self.analysis_duration)
        if utils.test_value(self.exit_code): dynamic_analysis_metadata_obj.set_Exit_Code(self.exit_code)
        analysis_obj.set_Dynamic_Analysis_Metadata(dynamic_analysis_metadata_obj)
        
        return analysis_obj
        
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
        