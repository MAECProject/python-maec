#MAEC Analysis Class

#Copyright (c) 2012, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v3.0
#Last updated 01/16/2013

import maec_package_1_0 as package_binding
import maec_bundle_3_0 as bundle_binding
        
class analysis:
    def __init__(self, generator, method = None, type = None, analysis_attributes_dict = None):
        self.generator = generator
        self.analysis = package_binding.AnalysisType(id=self.generator.generate_ana_id())
        if method is not None:
            self.analysis.set_method(method)
        if type is not None:
            self.analysis.set_type(type)
        self.analysis_attributes_dict = analysis_attributes_dict
        self.tool_list = package_binding.ToolListType()

    #"Public" methods
    def set_findings_bundle_reference(self, bundle_idref):
        bundle_reference = bundle_binding.BundleReferenceType(bundle_idref = bundle_idref)
        self.analysis.set_Findings_Bundle_Reference(bundle_reference)

    def set_summary(self, summary):
        self.analysis.set_Summary(summary)
   
    def add_tool(self, tool_dictionary):
        self.__create_tool(tool_dictionary)

    #Create and return the Analysis from the input dictionary
    @classmethod
    def create_from_dict(cls, analysis_attributes_dict):
        maec_analysis = package_binding.AnalysisType()
        for key, value in analysis_attributes_dict.items():
            if key == 'id': maec_analysis.set_id(value)
            elif key == 'type': maec_analysis.set_type(value)
            elif key == 'method' : maec_analysis.set_method(value)
            elif key == 'ordinal_position' : maec_analysis.set_ordinal_position(value)
            elif key == 'start_datetime' : maec_analysis.set_start_datetime(value)
            elif key == 'complete_datetime' : maec_analysis.set_complete_datetime(value)
            elif key == 'lastupdate_datetime' : maec_analysis.set_lastupdate_datetime(value)
            elif key == 'method' : maec_analysis.set_method(value)
            elif key == 'source' : 
                source_dict = value
                source = package_binding.SourceType()
                for source_key, source_value in source_dict.items(): 
                    if source_key == 'name': source.set_Name(source_value)
                    if source_key == 'method': source.set_Method(source_value)
                    if source_key == 'reference': source.set_Reference(source_value)
                    if source_key == 'organization': source.set_Organization(source_value)
                    if source_key == 'url': source.set_URL(source_value)
                if source.hasContent_(): maec_analysis.set_Source(source)
            elif key == 'analysts':
                contributors = value
                personnel = package_binding.cybox_common_types_1_0.PersonnelType()
                for contributor_dict in contributors:
                    contributor = bundle_binding.cybox_common_types_1_0.ContributorType()
                    for contributor_key, contributor_value in contributor_dict.items():
                        if contributor_key == 'role': contributor.set_Role(contributor_value)
                        if contributor_key == 'name': contributor.set_Name(contributor_value)
                        if contributor_key == 'email': contributor.set_Email(contributor_value)
                        if contributor_key == 'phone': contributor.set_Phone(contributor_value)
                        if contributor_key == 'organization': contributor.set_Organization(contributor_value)
                        if contributor_key == 'date': 
                            date_dict = contributor_value
                            date = bundle_binding.cybox_common_types_1_0.DateRangeType()
                            for date_key, date_value in date_dict.items():
                                if date_key == 'start_date' : date.set_start_date(date_value)
                                if date_key == 'end_date' : date.set_end_date(date_value)
                            if date.hasContent_():
                                contributor.set_Date(date)
                        if contributor_key == 'contribution_location': contributor.set_Contribution_Location(contributor_value)
                    if contributor.hasContent_(): personnel.add_Contributor(contributor)
                if personnel.hasContent_(): maec_analysis.set_Analysts(personnel)
            elif key == 'summary' : maec_analysis.set_Summary(value)
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
                if comment_list.hasContent_(): maec_analysis.set_Comments(comment_list)
            elif key == 'findings_bundle_reference' : 
                findings_bundle_reference = bundle_binding.BundleReferenceType(bundle_idref = value)
                maec_analysis.set_Findings_Bundle_Reference(findings_bundle_reference)
            elif key == 'tools':
                tools = value
                tools_list = package_binding.ToolListType()
                for tool_dict in tools:
                    tool = bundle_binding.cybox_common_types_1_0.ToolInformationType()
                    for tool_key, tool_value in tool_dict.items():
                        if tool_key == 'id' : tool.set_id(tool_value)
                        if tool_key == 'idref' : tool.set_idref(tool_value)
    def get(self):
        if self.tool_list.hasContent_():
            self.analysis.set_Tools(self.tool_list)
        return self.analysis
    
    #"Private" methods

    #Create the MAEC tool type
    def __create_tool(self, tool_dictionary):
        #Create the Tool and set its ID
        tool = package_binding.cybox_common_types_1_0.ToolInformationType(id=self.generator.generate_tol_id())
        for key, value in tool_dictionary.items():
            if key.lower() == 'description':
                if value is not None and len(value) > 0:
                    tool.set_Description(value)
            elif key.lower() == 'vendor':
                if value is not None and len(value) > 0:
                    tool.set_Vendor(value)
            elif key.lower() == 'name':
                if value is not None and len(value) > 0:
                    tool.set_Name(value)  
            elif key.lower() == 'version':
                if value is not None and len(value) > 0:
                    tool.set_Version(value)
        if tool.hasContent_():
            self.tool_list.add_Tool(tool)
    
    def __build__(self):
        if self.tool_list.hasContent_():
            self.analysis.set_Tools(tool_list)      
