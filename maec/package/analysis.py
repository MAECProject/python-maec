#MAEC Analysis Class

#Copyright (c) 2013, The MITRE Corporation
#All rights reserved.

#Compatible with MAEC v4.0
#Last updated 05/29/2013

from cybox.common import (PlatformSpecification, Personnel, StructuredText,
        ToolInformation)
from cybox.objects.system_object import System

import maec
import maec.bindings.maec_package as package_binding
from maec.bundle.bundle_reference import BundleReference


class Analysis(maec.Entity):
    def __init__(self, id, method = None, type = None, findings_bundle_reference = None):
        super(Analysis, self).__init__()
        self.id = id
        self.method = method
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
        self.tools = ToolList()
        self.dynamic_analysis_metadata = None
        self.analysis_environment = None
        self.report = None

    #"Public" methods
    def set_findings_bundle(self, bundle_id):
        self.findings_bundle_reference = BundleReference.from_dict({'bundle_idref' : bundle_id})
   
    def add_tool(self, tool):
        self.tools.append(tool)

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
        if self.tools: analysis_obj.set_Tools(self.tools.to_obj())
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
        if self.analysts is not None : analysis_dict['analysts'] = self.analysts.to_list()
        if self.summary is not None : analysis_dict['summary'] = self.summary.to_dict()
        if self.comments is not None : analysis_dict['comments'] = self.comments.to_list()
        if self.findings_bundle_reference is not None : analysis_dict['findings_bundle_reference'] = self.findings_bundle_reference.to_dict()
        if self.tools: analysis_dict['tools'] = self.tools.to_list()
        if self.dynamic_analysis_metadata is not None : analysis_dict['dynamic_analysis_metadata'] = self.dynamic_analysis_metadata.to_dict()
        if self.analysis_environment is not None : analysis_dict['analysis_environment'] = self.analysis_environment.to_dict()
        if self.report is not None : analysis_dict['report'] = self.report.to_dict()
        return analysis_dict

    #Create and return the Analysis from the input dictionary
    @staticmethod
    def from_obj(analysis_obj):
        if not analysis_obj:
            return None
        analysis_ = Analysis(None)
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
        analysis_.tools = ToolList.from_obj(analysis_obj.get_Tools())
        analysis_.dynamic_analysis_metadata = DynamicAnalysisMetadata.from_obj(analysis_obj.get_Dynamic_Analysis_Metadata())
        analysis_.analysis_environment = AnalysisEnvironment.from_obj(analysis_obj.get_Analysis_Environment())
        analysis_.report = StructuredText.from_obj(analysis_obj.get_Report())
        return analysis_

    #Create and return the Analysis from the input dictionary
    @staticmethod
    def from_dict(analysis_dict):
        if not analysis_dict:
            return None
        analysis_ = Analysis(None)
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
        analysis_.tools = ToolList.from_list(analysis_dict.get('tools', []))
        analysis_.dynamic_analysis_metadata = DynamicAnalysisMetadata.from_dict(analysis_dict.get('dynamic_analysis_metadata'))
        analysis_.analysis_environment = AnalysisEnvironment.from_dict(analysis_dict.get('analysis_environment'))
        analysis_.report = StructuredText.from_dict(analysis_dict.get('report'))
        return analysis_

class Comment(StructuredText):

    def __init__(self):
        super(Comment, self).__init__()
        self.author = None
        self.timestamp = None

    def is_plain(self):
        """Whether this can be represented as a string rather than a dictionary
        """
        return (super(Comment, self).is_plain() and 
                self.author is None and
                self.timestamp is None)

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
        comment_.author = comment_obj.get_author()
        comment_.timestamp = comment_obj.get_timestamp()
        return comment_

class CommentList(maec.EntityList):
    _contained_type = Comment
    _binding_class = package_binding.CommentListType
    _binding_var = "Comment"

class DynamicAnalysisMetadata(maec.Entity):

    def __init__(self):
        super(DynamicAnalysisMetadata, self).__init__()
        self.command_line = None
        self.analysis_duration = None
        self.exit_code = None

    def to_obj(self):
        dynamic_analysis_metadata_obj = package_binding.DynamicAnalysisMetadataType()
        if self.command_line is not None : dynamic_analysis_metadata_obj.set_Command_Line(self.command_line)
        if self.analysis_duration is not None : dynamic_analysis_metadata_obj.set_Analysis_Duration(self.analysis_duration)
        if self.exit_code is not None : dynamic_analysis_metadata_obj.set_Exit_Code(self.exit_code)
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
    def from_obj(dynamic_analysis_metadata_obj):
        if not dynamic_analysis_metadata_obj:
            return None
        dynamic_analysis_metadata_ = DynamicAnalysisMetadata()
        dynamic_analysis_metadata_.command_line = dynamic_analysis_metadata_obj.get_Command_Line()
        dynamic_analysis_metadata_.analysis_duration = dynamic_analysis_metadata_obj.get_Analysis_Duration()
        dynamic_analysis_metadata_.exit_code = dynamic_analysis_metadata_obj.get_Exit_Code()
        return dynamic_analysis_metadata_

class AnalysisEnvironment(maec.Entity):

    def __init__(self):
        super(AnalysisEnvironment, self).__init__()
        self.hypervisor_host_system = None
        self.analysis_systems = None
        self.network_infrastructure = None

    def to_obj(self):
        analysis_environment_obj = package_binding.AnalysisEnvironmentType()
        if self.hypervisor_host_system is not None : analysis_environment_obj.set_Hypervisor_Host_System(self.hypervisor_host_system.to_obj())
        if self.analysis_systems is not None : analysis_environment_obj.set_Analysis_Systems(self.analysis_systems.to_obj())
        if self.network_infrastructure is not None : analysis_environment_obj.set_Network_Infrastructure(self.network_infrastructure.to_obj())
        return analysis_environment_obj

    def to_dict(self):
        analysis_environment_dict = {}
        if self.hypervisor_host_system is not None : analysis_environment_dict['hypervisor_host_system'] = self.hypervisor_host_system.to_dict()
        if self.analysis_systems is not None : analysis_environment_dict['analysis_systems'] = self.analysis_systems.to_list()
        if self.network_infrastructure is not None : analysis_environment_dict['network_infrastructure'] = self.network_infrastructure.to_dict()
        return analysis_environment_obj

    @staticmethod
    def from_dict(analysis_environment_dict):
        if not analysis_environment_dict:
            return None
        analysis_environment_ = AnalysisEnvironment()
        analysis_environment_.hypervisor_host_system = HypervisorHostSystem.from_dict(analysis_environment_dict.get('hypervisor_host_system'))
        analysis_environment_.analysis_systems = AnalysisSystemList.from_list(analysis_environment_dict.get('analysis_systems'))
        analysis_environment_.network_infrastructure = NetworkInfrastructure.from_dict(analysis_environment_dict.get('network_infrastructure'))
        return analysis_environment_

    @staticmethod
    def from_obj(analysis_environment_obj):
        if not analysis_environment_obj:
            return None
        analysis_environment_ = AnalysisEnvironment()
        analysis_environment_.hypervisor_host_system = HypervisorHostSystem.from_obj(analysis_environment_obj.get_Hypervisor_Host_System())
        analysis_environment_.analysis_systems = AnalysisSystemList.from_obj(analysis_environment_obj.get_Analysis_Systems())
        analysis_environment_.network_infrastructure = NetworkInfrastructure.from_obj(analysis_environment_obj.get_Network_Infrastructure())
        return analysis_environment_

class HypervisorHostSystem(System):

    def __init__(self):
        super(HypervisorHostSystem, self).__init__()
        self.vm_hypervisor = None

    def to_obj(self):
        hypervisor_host_system_obj = super(HypervisorHostSystem, self).to_obj(package_binding.HypervisorHostSystemType())
        if self.vm_hypervisor is not None : hypervisor_host_system_obj.set_VM_Hypervisor(self.vm_hypervisor.to_obj())
        return hypervisor_host_system_obj

    def to_dict(self):
        hypervisor_host_system_dict = super(HypervisorHostSystem, self).to_dict()
        if self.vm_hypervisor is not None : hypervisor_host_system_dict['vm_hypervisor'] = self.vm_hypervisor.to_dict()
        return hypervisor_host_system_dict

    @staticmethod
    def from_dict(hypervisor_host_system_dict):
        if not hypervisor_host_system_dict:
            return None
        hypervisor_host_system_ = System.from_dict(hypervisor_host_system_dict, HypervisorHostSystem())
        hypervisor_host_system_.vm_hypervisor = PlatformSpecification.from_dict(hypervisor_host_system_dict.get('vm_hypervisor'))
        return hypervisor_host_system_

    @staticmethod
    def from_obj(hypervisor_host_system_obj):
        if not hypervisor_host_system_obj:
            return None
        hypervisor_host_system_ = System.from_obj(hypervisor_host_system_obj, HypervisorHostSystem())
        hypervisor_host_system_.vm_hypervisor = PlatformSpecification.from_obj(hypervisor_host_system_obj.get_VM_Hypervisor())
        return hypervisor_host_system_

class AnalysisSystem(System):
    def __init__(self):
        super(AnalysisSystem, self).__init__()
        self.installed_programs = InstalledPrograms()

    def to_obj(self):
        analysis_system_obj = super(AnalysisSystem, self).to_obj(package_binding.AnalysisSystemType())
        if len(self.installed_programs) > 0 : analysis_system_obj.set_Installed_Programs(self.installed_programs.to_obj())
        return analysis_system_obj

    def to_dict(self):
        analysis_system_dict = super(AnalysisSystem, self).to_dict()
        if len(self.installed_programs) > 0 : analysis_system_dict['installed_programs'] = self.installed_programs.to_list()
        return analysis_system_dict

    @staticmethod
    def from_dict(analysis_system_dict):
        if not analysis_system_dict:
            return None
        analysis_system_ = System.from_dict(AnalysisSystem, AnalysisSystem())
        analysis_system_.installed_programs = InstalledPrograms.from_list(analysis_system_dict.get('installed_programs'))
        return analysis_system_

    @staticmethod
    def from_obj(analysis_system_obj):
        if not analysis_system_obj:
            return None
        analysis_system_ = System.from_obj(AnalysisSystem, AnalysisSystem())
        if analysis_system_obj.get_Installed_Programs() is not None : 
            analysis_system_.installed_programs = InstalledPrograms.from_obj(analysis_system_obj.get_Installed_Programs())
        return analysis_system_


class InstalledPrograms(maec.EntityList):
    _contained_type = PlatformSpecification
    _binding_class = package_binding.InstalledProgramsType
    _binding_var = "Program"

class AnalysisSystemList(maec.EntityList):
    _contained_type = AnalysisSystem
    _binding_class = package_binding.AnalysisSystemListType
    _binding_var = "Analysis_System"

class NetworkInfrastructure(maec.Entity):
    def __init__(self):
        super(NetworkInfrastructure, self).__init__()
        self.captured_protocols = CapturedProtocolList()

    def to_obj(self):
        network_infrastructure_obj = package_binding.NetworkInfrastructureType()
        if len(self.captured_protocols) > 0: network_infrastructure_obj.set_Captured_Protocols(self.captured_protocols.to_obj())
        return network_infrastructure_obj

    def to_dict(self):
        network_infrastructure_dict = {}
        if len(self.captured_protocols) > 0: network_infrastructure_dict['captured_protocols'] = self.captured_protocols.to_list()
        return network_infrastructure_dict

    @staticmethod
    def from_dict(network_infrastructure_dict):
        if not network_infrastructure_dict:
            return None
        network_infrastructure_ = NetworkInfrastructure()
        network_infrastructure_.captured_protocols = CapturedProtocolList.from_list(network_infrastructure_dict.get('captured_protocols'))
        return network_infrastructure_

    @staticmethod
    def from_obj(network_infrastructure_obj):
        if not network_infrastructure_obj:
            return None
        network_infrastructure_ = NetworkInfrastructure()
        if network_infrastructure_obj.get_Captured_Protocols() is not None :
            network_infrastructure_.captured_protocols = CapturedProtocolList.from_obj(network_infrastructure_obj.get_Captured_Protocols())
        return network_infrastructure_

class CapturedProtocol(maec.Entity):
    def __init__(self):
        super(CapturedProtocol, self).__init__()
        self.layer7_protocol = None
        self.layer4_protocol = None
        self.port_number = None
        self.interaction_level = None

    def to_obj(self):
        captured_protocol_obj = package_binding.CapturedProtocolType()
        if self.layer7_protocol is not None : captured_protocol_obj.set_layer7_protocol(self.layer7_protocol)
        if self.layer4_protocol is not None : captured_protocol_obj.set_layer4_protocol(self.layer4_protocol)
        if self.port_number is not None : captured_protocol_obj.set_port_number(self.port_number)
        if self.interaction_level is not None : captured_protocol_obj.set_interaction_level(self.interaction_level)
        return captured_protocol_obj

    def to_dict(self):
        captured_protocol_dict = {}
        if self.layer7_protocol is not None : captured_protocol_dict['layer7_protocol'] = self.layer7_protocol
        if self.layer4_protocol is not None : captured_protocol_dict['layer4_protocol'] = self.layer4_protocol
        if self.port_number is not None : captured_protocol_dict['port_number'] = self.port_number
        if self.interaction_level is not None : captured_protocol_dict['interaction_level'] = self.interaction_level
        return captured_protocol_dict

    @staticmethod
    def from_dict(captured_protocol_dict):
        if not captured_protocol_dict:
            return None
        captured_protocol_ = CapturedProtocol()
        captured_protocol_.layer7_protocol = captured_protocol_dict.get('layer7_protocol')
        captured_protocol_.layer4_protocol = captured_protocol_dict.get('layer4_protocol')
        captured_protocol_.port_number = captured_protocol_dict.get('port_number')
        captured_protocol_.interaction_level = captured_protocol_dict.get('interaction_level')
        return captured_protocol_

    @staticmethod
    def from_obj(captured_protocol_obj):
        if not captured_protocol_obj:
            return None
        captured_protocol_ = CapturedProtocol()
        captured_protocol_.layer7_protocol = captured_protocol_obj.get_layer7_protocol()
        captured_protocol_.layer4_protocol = captured_protocol_dict.get_layer4_protocol()
        captured_protocol_.port_number = captured_protocol_dict.get_port_number()
        captured_protocol_.interaction_level = captured_protocol_dict.get_interaction_level()
        return captured_protocol_

class CapturedProtocolList(maec.EntityList):
    _contained_type = CapturedProtocol
    _binding_class = package_binding.CapturedProtocolListType
    _binding_var = "Protocol"

class ToolList(maec.EntityList):
    _contained_type = ToolInformation
    _binding_class = package_binding.ToolListType
    _binding_var = "Tool"
    
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



