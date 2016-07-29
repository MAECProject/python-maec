# MAEC Analysis Class

# Copyright (c) 2015, The MITRE Corporation
# All rights reserved

from mixbox import fields
from mixbox import idgen

from cybox.common import (PlatformSpecification, Personnel, StructuredText,
        ToolInformation)
from cybox.objects.system_object import System

import maec
from . import _namespace
import maec.bindings.maec_package as package_binding
from maec.bundle import BundleReference

class Source(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.SourceType
    _namespace = _namespace

    name = fields.TypedField("Name")
    method = fields.TypedField("Method")
    reference = fields.TypedField("Reference")
    organization = fields.TypedField("Organization")
    url = fields.TypedField("URL")
    
    def __init__(self):
        super(Source, self).__init__()

class Comment(StructuredText):
    _binding = package_binding
    _binding_class = package_binding.CommentType
    _namespace = _namespace

    author = fields.TypedField("author")
    timestamp = fields.TypedField("timestamp")
    observation_name = fields.TypedField("observation_name")

    def __init__(self, value=None):
        super(Comment, self).__init__(value)

    def is_plain(self):
        """Whether this can be represented as a string rather than a dictionary
        """
        return (super(Comment, self).is_plain() and 
                self.author is None and
                self.timestamp is None and 
                self.observation_name is None)

    def to_obj(self, ns_info=None):
        comment_obj = super(Comment, self).to_obj()

        if self.author:
            comment_obj.author = self.author
        if self.timestamp:
            comment_obj.timestamp = self.timestamp
        if self.observation_name:
            comment_obj.observation_name = self.observation_name

        return comment_obj

    def to_dict(self):
        comment_dict = super(Comment, self).to_dict()
        if self.author:
            comment_dict['author'] = self.author
        if self.timestamp:
            comment_dict['timestamp'] = self.timestamp
        if self.observation_name:
            comment_dict['observation_name'] = self.observation_name

        return comment_dict

    @classmethod
    def from_obj(cls, cls_obj):
        if not cls_obj:
            return None

        comment = super(Comment, cls).from_obj(cls_obj)
        comment.value = cls_obj.valueOf_

        if cls_obj.author:
            comment.author = cls_obj.author
        if cls_obj.timestamp:
            comment.timestamp = cls_obj.timestamp
        if cls_obj.observation_name:
            comment.observation_name = cls_obj.observation_name

        return comment

    @classmethod
    def from_dict(cls, cls_dict):
        if not cls_dict:
            return None

        if not isinstance(cls_dict, dict):
            comment = cls(cls_dict)
        else:
            super(Comment, cls).from_dict(cls_dict)
            comment.author = cls_dict.get('author')
            comment.timestamp = cls_dict.get('timestamp')
            comment.observation_name = cls_dict.get('observation_name')

        return comment

class CommentList(maec.EntityList):
    _binding_class = package_binding.CommentListType
    _namespace = _namespace
    comment = fields.TypedField("Comment", Comment, multiple=True)

class ToolList(maec.EntityList):
    _binding_class = package_binding.ToolListType
    _namespace = _namespace
    tool = fields.TypedField("Tool", ToolInformation, multiple=True)

class DynamicAnalysisMetadata(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.DynamicAnalysisMetadataType
    _namespace = _namespace

    command_line = fields.TypedField("Command_Line")
    analysis_duration = fields.TypedField("Analysis_Duration")
    exit_code = fields.TypedField("Exit_Code")
    #raised_exception = fields.TypedField("Raised_Exception", MalwareException)
    
    def __init__(self):
        super(DynamicAnalysisMetadata, self).__init__()

class HypervisorHostSystem(System):
    _binding = package_binding
    _binding_class = package_binding.HypervisorHostSystemType
    _namespace = _namespace

    vm_hypervisor = fields.TypedField("VM_Hypervisor", PlatformSpecification)

    def __init__(self):
        super(HypervisorHostSystem, self).__init__()
        
class InstalledPrograms(maec.EntityList):
    _binding_class = package_binding.InstalledProgramsType
    _namespace = _namespace
    program = fields.TypedField("Program", PlatformSpecification, multiple=True)
        
class AnalysisSystem(System):
    _binding = package_binding
    _binding_class = package_binding.AnalysisSystemType
    _namespace = _namespace

    installed_programs = fields.TypedField("Installed_Programs", InstalledPrograms)

    def __init__(self):
        super(AnalysisSystem, self).__init__()
        self.installed_programs = InstalledPrograms()

class AnalysisSystemList(maec.EntityList):
    _binding_class = package_binding.AnalysisSystemListType
    _namespace = _namespace
    analysis_system = fields.TypedField("Analysis_System", AnalysisSystem, multiple=True)

class CapturedProtocol(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.CapturedProtocolType
    _namespace = _namespace

    layer7_protocol = fields.TypedField("layer7_protocol")
    layer4_protocol = fields.TypedField("layer4_protocol")
    port_number = fields.TypedField("port_number")
    interaction_level = fields.TypedField("interaction_level")

    def __init__(self):
        super(CapturedProtocol, self).__init__()

class CapturedProtocolList(maec.EntityList):
    _binding_class = package_binding.CapturedProtocolListType
    _namespace = _namespace
    protocol = fields.TypedField("Protocol", CapturedProtocol, multiple=True)

class NetworkInfrastructure(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.NetworkInfrastructureType
    _namespace = _namespace

    captured_protocols = fields.TypedField("Captured_Protocols", CapturedProtocolList)

    def __init__(self):
        super(NetworkInfrastructure, self).__init__()
        self.captured_protocols = CapturedProtocolList()

class AnalysisEnvironment(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.AnalysisEnvironmentType
    _namespace = _namespace

    hypervisor_host_system = fields.TypedField("Hypervisor_Host_System", HypervisorHostSystem)
    analysis_systems = fields.TypedField("Analysis_Systems", AnalysisSystemList)
    network_infrastructure = fields.TypedField("Network_Infrastructure", NetworkInfrastructure)

    def __init__(self):
        super(AnalysisEnvironment, self).__init__()

class Analysis(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.AnalysisType
    _namespace = _namespace

    id_ = fields.TypedField("id")
    method = fields.TypedField("method")
    type_ = fields.TypedField("type")
    ordinal_position = fields.TypedField("ordinal_position")
    start_datetime = fields.TypedField("start_datetime")
    complete_datetime = fields.TypedField("complete_datetime")
    lastupdate_datetime = fields.TypedField("lastupdate_datetime")
    source = fields.TypedField("Source", Source)
    analysts = fields.TypedField("Analysts", Personnel)
    summary = fields.TypedField("Summary", StructuredText)
    comments = fields.TypedField("Comments", CommentList)
    findings_bundle_reference = fields.TypedField("Findings_Bundle_Reference", BundleReference, multiple = True)
    tools = fields.TypedField("Tools", ToolList)
    dynamic_analysis_metadata = fields.TypedField("Dynamic_Analysis_Metadata", DynamicAnalysisMetadata)
    analysis_environment = fields.TypedField("Analysis_Environment", AnalysisEnvironment)
    report = fields.TypedField("Report", StructuredText)

    def __init__(self, id = None, method = None, type = None, findings_bundle_reference = []):
        super(Analysis, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = idgen.create_id(prefix="analysis")
        self.method = method
        self.type_ = type
        self.findings_bundle_reference = findings_bundle_reference

    #"Public" methods
    # set the findings_bundle_reference values; accepts a list of bundle ID values
    def set_findings_bundle(self, bundle_id):
        self.findings_bundle_reference = [BundleReference.from_dict({'bundle_idref' : bundle_id})]
   
   # add a tool to this Anaysis's ToolList
    def add_tool(self, tool):
        if not self.tools:
            self.tools = ToolList()
        self.tools.append(tool)



    





