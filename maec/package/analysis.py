#MAEC Analysis Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/13/2013

import maec
import maec.bindings.maec_package as package_binding
from cybox.common.structured_text import StructuredText
from cybox.common.tools import ToolInformationList
from cybox.common.personnel import Personnel
from maec.bundle.bundle_reference import BundleReference
        
class Analysis(maec.Entity):
    def __init__(self, id, generator, method = None, type = None, findings_bundle_reference = None):
        super(Analysis, self).__init__()
        if id is not None:
            self.id = id
        elif generator is not None:
            self.generator = generator
            self.id = self.generator.generate_analysis_id()
        else:
            raise Exception("Must specify id or generator for Analysis constructor")
        if method is not None:
            self.method = method
        if type is not None:
            self.type = type
        self.ordinal_position = None
        self.start_datetime = None
        self.complete_datetime = None
        self.lastupdate_datetime = None
        self.source = None
        self.analysts = None
        self.summary = None
        self.comments = None
        self.findings_bundle_reference = findings_bundle_reference
        self.tools = None
        self.dynamic_analysis_metadata = None
        self.analysis_environment = None
        self.report = None

    #"Public" methods
    def set_findings_bundle_reference(self, bundle_idref):
        self.bundle_idref = bundle_idref

    def set_summary(self, summary):
        self.analysis.set_Summary(summary)
   
    def add_tool(self, tool):
        self.tool_list.append(tool)

    def get_tools(self):
        return self.tool_list

    def set_type(self, type):
        self.type = type

    def set_method(self, method):
        self.method = method

    def set_complete_datetime(self, complete_datetime):
        self.complete_datetime = complete_datetime

    #def set_command_line(self, command_line):
    #    self.command_line = command_line

    #def set_analysis_duration(self, analysis_duration):
    #    self.analysis_duration = analysis_duration

    #def set_exit_code(self, exit_code):
    #    self.exit_code = exit_code

    #Return a bindings object
    def to_obj(self):
        analysis_obj = package_binding.AnalysisType()
        if self.id is not None : analysis_obj.set_id(self.id)
        if self.method is not None: analysis_obj.set_method(self.method)
        if self.type is not None: analysis_obj.set_type(self.type)
        if self.ordinal_position is not None : analysis_obj.set_ordinal_position(self.ordinal_position)
        if self.complete_datetime is not None: analysis_obj.set_complete_datetime(self.complete_datetime)
        if self.start_datetime is not None : analysis_obj.set_start_datetime(self.start_datetime)
        if self.lastupdate_datetime is not None : analysis_obj.set_lastupdate_datetime(self.lastupdate_datetime)
        if self.source is not None : analysis_obj.set_Source(self.source.to_obj())
        if self.analysts is not None : analysis_obj.set_Analysts(self.analysts.to_obj())
        if self.summary is not None : analysis_obj.set_Summary(self.summary.to_obj())
        if self.comments is not None : analysis_obj.set_Comments(self.comments.to_obj())
        if self.findings_bundle_reference is not None : analysis_obj.set_Findings_Bundle_Reference(self.findings_bundle_reference.to_obj())
        if self.tools is not None : analysis_obj.set_Tools(self.tools.to_obj())
        if self.dynamic_analysis_metadata is not None : analysis_obj.set_Dynamic_Analysis_Metadata(self.dynamic_analysis_metadata.to_obj())
        if self.analysis_environment is not None : analysis_obj.set_Analysis_Environment(self.analysis_environment.to_obj())
        if self.report is not None : analysis_obj.set_Report(self.report.to_obj())
        return analysis_obj
        
    def to_dict(self):
        analysis_dict = {}
        if self.id is not None: analysis_dict['id'] = self.id
        if self.method is not None: analysis_dict['method'] = self.method
        if self.type is not None: analysis_dict['type'] = self.type
        if self.ordinal_position is not None : analysis_dict['ordinal_position'] = self.ordinal_position
        if self.complete_datetime is not None: analysis_dict['complete_datetime'] = self.complete_datetime
        if self.start_datetime is not None : analysis_dict['start_datetime'] = self.start_datetime
        if self.lastupdate_datetime is not None : analysis_dict['lastupdate_datetime'] = self.lastupdate_datetime
        if self.source is not None : analysis_dict['source'] = self.source.to_dict()
        if self.analysts is not None : analysis_dict['analysts'] = self.analysts.to_dict()
        if self.summary is not None : analysis_dict['summary'] = self.summary.to_dict()
        if self.comments is not None : analysis_dict['comments'] = self.comments.to_dict()
        if self.findings_bundle_reference is not None : analysis_dict['findings_bundle_reference'] = self.findings_bundle_reference.to_dict()
        if self.tools is not None : analysis_dict['tools'] = self.tools.to_dict()
        if self.dynamic_analysis_metadata is not None : analysis_dict['dynamic_analysis_metadata'] = self.dynamic_analysis_metadata.to_dict()
        if self.analysis_environment is not None : analysis_dict['analysis_environment'] = self.analysis_environment.to_dict()
        if self.report is not None : analysis_dict['report'] = self.report.to_dict()
        return analysis_dict

    #Create and return the Analysis from the input dictionary
    @staticmethod
    def from_obj(analysis_obj):
        if not analysis_obj:
            return None
        analysis_ = Analysis()
        analysis_.id = analysis_obj.get_id()
        analysis_.method = analysis_obj.get_method()
        analysis_.type = analysis_obj.get_type()
        analysis_.ordinal_position = analysis_obj.get_ordinal_position()
        analysis_.complete_datetime = analysis_obj.get_complete_datetime()
        analysis_.start_datetime = analysis_obj.get_start_datetime()
        analysis_.lastupdate_datetime = analysis_obj.get_lastupdate_datetime()
        analysis_.source = Source.from_obj(analysis_obj.get_Source())
        analysis_.analysts = Personnel.from_obj(analysis_obj.get_Analysts())
        analysis_.summary = StructuredText.from_obj(analysis_obj.get_Summary())
        analysis_.comments = CommentList.from_obj(analysis_obj.get_Comments())
        analysis_.findings_bundle_reference = BundleReference.from_obj(analysis_obj.get_Findings_Bundle_Reference())
        analysis_.tools = ToolInformationList.from_obj(analysis_obj.get_Tools())
        analysis_.dynamic_analysis_metadata = DynamicAnalysisMetadata.from_obj(analysis_obj.get_Dynamic_Analysis_Metadata())
        analysis_.analysis_environment = AnalysisEnvironment.from_obj(analysis_obj.get_Analysis_Environment())
        analysis_.report = StructuredText.from_obj(analysis_obj.get_Report())
        return analysis_

    #Create and return the Analysis from the input dictionary
    @staticmethod
    def from_dict(analysis_dict):
        if not analysis_dict:
            return None
        analysis_ = Analysis()
        analysis_.id = analysis_dict.get('id')
        analysis_.method = analysis_dict.get('method')
        analysis_.type = analysis_dict.get('type')
        analysis_.ordinal_position = analysis_dict.get('ordinal_position')
        analysis_.complete_datetime = analysis_dict.get('complete_datetime')
        analysis_.start_datetime = analysis_dict.get('start_datetime')
        analysis_.lastupdate_datetime = analysis_dict.get('lastupdate_datetime')
        analysis_.source = Source.from_dict(analysis_dict.get('source'))
        analysis_.analysts = Personnel.from_list(analysis_dict.get('analysts'))
        analysis_.summary = StructuredText.from_dict(analysis_dict.get('summary'))
        analysis_.comments = CommentList.from_list(analysis_dict.get('comments'))
        analysis_.findings_bundle_reference = BundleReference.from_dict(analysis_dict.get('findings_bundle_reference'))
        analysis_.tools = ToolInformationList.from_list(analysis_dict.get('tools'))
        analysis_.dynamic_analysis_metadata = DynamicAnalysisMetadata.from_dict(analysis_dict.get('dynamic_analysis_metadata'))
        analysis_.analysis_environment = AnalysisEnvironment.from_dict(analysis_dict.get('analysis_environment'))
        analysis_.report = StructuredText.from_dict(analysis_dict.get('report'))
        return analysis_

class Comment(StructuredText):

    def __init__(self):
        super(Comment, self).__init__()
        self.author = None
        self.timestamp = None

    def to_obj(self):
        comment_obj = super(Comment, self).to_obj(package_binding.CommentType())
        if self.author is not None : comment_obj.set_author(self.author)
        if self.timestamp is not None : comment_obj.set_timestamp(self.timestamp)
        return comment_obj

    def to_dict(self):
        comment_dict = super(Comment, self).to_dict()
        if self.author is not None : comment_dict['author'] = self.author
        if self.timestamp is not None : comment_dict['timestamp'] = self.timestamp
        return comment_dict

    @staticmethod
    def from_dict(comment_dict):
        if not comment_dict:
            return None
        comment_ = StructuredText.from_dict(comment_dict, Comment())
        comment_.author = comment_dict.get('author')
        comment_.timestamp = comment_dict.get('timestamp')
        return comment_

    @staticmethod
    def from_obj(comment_obj):
        if not comment_obj:
            return None
        comment_ = StructuredText.from_obj(comment_obj, Comment())
        comment_.author = comment_obj.get_Author()
        comment_.timestamp = comment_obj.get_Timestamp()
        return comment_

class CommentList(maec.EntityList):
    _contained_type = Comment
    _binding_class = package_binding.CommentListType

    def __init__(self):
        super(Objects, self).__init__()

    @staticmethod
    def _set_list(binding_obj, list_):
        binding_obj.set_Comment(list_)

    @staticmethod
    def _get_list(binding_obj):
        return binding_obj.get_Comment()


class DynamicAnalysisMetadata(maec.Entity):

    def __init__(self):
        super(DynamicAnalysisMetadata, self).__init__()
        self.command_line = None
        self.analysis_duration = None
        self.exit_code = None

    def to_obj(self):
        dynamic_analysis_metadata_obj = package_binding.DynamicAnalysisMetadataType()
        if self.command_line is not None : dynamic_analysis_metadata_obj.set_command_line(self.command_line)
        if self.analysis_duration is not None : dynamic_analysis_metadata_obj.set_analysis_duration(self.analysis_duration)
        if self.exit_code is not None : dynamic_analysis_metadata_obj.set_exit_code(self.exit_code)
        return dynamic_analysis_metadata_obj

    def to_dict(self):
        dynamic_analysis_metadata_dict = {}
        if self.command_line is not None : dynamic_analysis_metadata_dict['command_line'] = self.command_line
        if self.analysis_duration is not None : dynamic_analysis_metadata_dict['analysis_duration'] = self.analysis_duration
        if self.exit_code is not None : dynamic_analysis_metadata_dict['exit_code'] = self.exit_code
        return dynamic_analysis_metadata_dict

    @staticmethod
    def from_dict(dynamic_analysis_metadata_dict):
        if not dynamic_analysis_metadata_dict:
            return None
        dynamic_analysis_metadata_ = DynamicAnalysisMetadata()
        dynamic_analysis_metadata_.command_line = dynamic_analysis_metadata_dict.get('command_line')
        dynamic_analysis_metadata_.analysis_duration = dynamic_analysis_metadata_dict.get('analysis_duration')
        dynamic_analysis_metadata_.exit_code = dynamic_analysis_metadata_dict.get('exit_code')
        return dynamic_analysis_metadata_

    @staticmethod
    def from_dict(dynamic_analysis_metadata_obj):
        if not dynamic_analysis_metadata_obj:
            return None
        dynamic_analysis_metadata_ = DynamicAnalysisMetadata()
        dynamic_analysis_metadata_.command_line = dynamic_analysis_metadata_obj.get_command_line()
        dynamic_analysis_metadata_.analysis_duration = dynamic_analysis_metadata_obj.get_analysis_duration()
        dynamic_analysis_metadata_.exit_code = dynamic_analysis_metadata_obj.get_exit_code()
        return dynamic_analysis_metadata_

class AnalysisEnvironment(maec.Entity):
    #TODO: Flesh out class
    def __init__(self):
        self.hypervisor_host_system = None
        self.analysis_systems = None
        self.network_infrastructure = None

    def to_obj(self):
        pass

    def to_dict(self):
        pass

    @staticmethod
    def from_dict(analysis_environment_dict):
        pass

    @staticmethod
    def from_dict(analysis_environment_obj):
        pass

class Source(maec.Entity):

    def __init__(self):
        super(Source, self).__init__()
        self.name = None
        self.method = None
        self.reference = None
        self.organization = None
        self.url = None

    def to_obj(self):
        source_obj = package_binding.SourceType()
        if self.name is not None : source_obj.set_Name(self.name)
        if self.method is not None : source_obj.set_Method(self.method)
        if self.reference is not None : source_obj.set_Reference(self.reference)
        if self.organization is not None : source_obj.set_Organization(self.organization)
        if self.url is not None : source_obj.set_URL(self.url)
        return source_obj

    def to_dict(self):
        source_dict = {}
        if self.name is not None : source_dict['name'] = self.name
        if self.method is not None : source_dict['method'] = self.method
        if self.reference is not None : source_dict['reference'] = self.reference
        if self.organization is not None : source_dict['organization'] = self.organization
        if self.url is not None : source_dict['url'] = self.url
        return source_dict

    @staticmethod
    def from_dict(source_dict):
        if not source_dict:
            return None
        source_ = Source()
        source_.name = source_dict.get('name')
        source_.method = source_dict.get('method')
        source_.reference = source_dict.get('reference')
        source_.organization = source_dict.get('organization')
        source_.url = source_dict.get('url')
        return source_

    @staticmethod
    def from_obj(source_obj):
        if not source_obj:
            return None
        source_ = Source()
        source_.name = source_obj.get_Name()
        source_.method = source_obj.get_Method()
        source_.reference = source_obj.get_Reference()
        source_.organization = source_obj.get_Organization()
        source_.url = source_obj.get_URL()
        return source_



