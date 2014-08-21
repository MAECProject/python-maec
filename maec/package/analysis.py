#MAEC Analysis Class

#Copyright (c) 2014, The MITRE Corporation
#All rights reserved

#Compatible with MAEC v4.1
#Last updated 08/20/2014

import cybox
from cybox.common import (PlatformSpecification, Personnel, StructuredText,
        ToolInformation)
from cybox.objects.system_object import System

import maec
import maec.bindings.maec_package as package_binding
from maec.bundle.bundle_reference import BundleReference

class Source(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.SourceType
    _namespace = maec.package._namespace

    name = cybox.TypedField("name")
    method = cybox.TypedField("method")
    reference = cybox.TypedField("reference")
    organization = cybox.TypedField("organization")
    url = cybox.TypedField("url")
    
    def __init__(self):
        super(Source, self).__init__()
        self.name = None
        self.method = None
        self.reference = None
        self.organization = None
        self.url = None

class Comment(StructuredText):
    _binding = package_binding
    _binding_class = package_binding.CommentType
    _namespace = maec.package._namespace

    author = cybox.TypedField("author")
    timestamp = cybox.TypedField("timestamp")
    observation_name = cybox.TypedField("observation_name")

    def __init__(self):
        super(Comment, self).__init__()
        self.author = None
        self.timestamp = None
        self.observation_name = None

    def is_plain(self):
        """Whether this can be represented as a string rather than a dictionary
        """
        return (super(Comment, self).is_plain() and 
                self.author is None and
                self.timestamp is None and 
                self.observation_name is None)

class CommentList(maec.EntityList):
    _contained_type = Comment
    _binding_class = package_binding.CommentListType
    _binding_var = "Comment"
    _namespace = maec.package._namespace

class ToolList(maec.EntityList):
    _contained_type = ToolInformation
    _binding_class = package_binding.ToolListType
    _binding_var = "Tool"
    _namespace = maec.package._namespace

class DynamicAnalysisMetadata(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.DynamicAnalysisMetadataType
    _namespace = maec.package._namespace

    command_line = cybox.TypedField("command_line")
    analysis_duration = cybox.TypedField("analysis_duration")
    exit_code = cybox.TypedField("exit_code")
    #raised_exception = cybox.TypedField("raised_exception", MalwareException)
    
    def __init__(self):
        super(DynamicAnalysisMetadata, self).__init__()
        self.command_line = None
        self.analysis_duration = None
        self.exit_code = None

class HypervisorHostSystem(System):
    _binding = package_binding
    _binding_class = package_binding.HypervisorHostSystemType
    _namespace = maec.package._namespace

    vm_hypervisor = cybox.TypedField("vm_hypervisor", PlatformSpecification)

    def __init__(self):
        super(HypervisorHostSystem, self).__init__()
        self.vm_hypervisor = None
        
class InstalledPrograms(maec.EntityList):
    _contained_type = PlatformSpecification
    _binding_class = package_binding.InstalledProgramsType
    _binding_var = "Program"
    _namespace = maec.package._namespace
        
class AnalysisSystem(System):
    _binding = package_binding
    _binding_class = package_binding.AnalysisSystemType
    _namespace = maec.package._namespace

    installed_programs = cybox.TypedField("installed_programs", InstalledPrograms)

    def __init__(self):
        super(AnalysisSystem, self).__init__()
        self.installed_programs = InstalledPrograms()

class AnalysisSystemList(maec.EntityList):
    _contained_type = AnalysisSystem
    _binding_class = package_binding.AnalysisSystemListType
    _binding_var = "Analysis_System"
    _namespace = maec.package._namespace

class CapturedProtocol(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.CapturedProtocolType
    _namespace = maec.package._namespace

    layer7_protocol = cybox.TypedField("layer7_protocol")
    layer4_protocol = cybox.TypedField("layer4_protocol")
    port_number = cybox.TypedField("port_number")
    interaction_level = cybox.TypedField("interaction_level")

    def __init__(self):
        super(CapturedProtocol, self).__init__()
        self.layer7_protocol = None
        self.layer4_protocol = None
        self.port_number = None
        self.interaction_level = None

class CapturedProtocolList(maec.EntityList):
    _contained_type = CapturedProtocol
    _binding_class = package_binding.CapturedProtocolListType
    _binding_var = "Protocol"
    _namespace = maec.package._namespace

class NetworkInfrastructure(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.NetworkInfrastructureType
    _namespace = maec.package._namespace

    captured_protocols = cybox.TypedField("captured_protocols", CapturedProtocolList)

    def __init__(self):
        super(NetworkInfrastructure, self).__init__()
        self.captured_protocols = CapturedProtocolList()

class AnalysisEnvironment(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.AnalysisEnvironmentType
    _namespace = maec.package._namespace

    hypervisor_host_system = cybox.TypedField("hypervisor_host_system", HypervisorHostSystem)
    analysis_systems = cybox.TypedField("analysis_systems", AnalysisSystemList)
    network_infrastructure = cybox.TypedField("network_infrastructure", NetworkInfrastructure)

    def __init__(self):
        super(AnalysisEnvironment, self).__init__()
        self.hypervisor_host_system = None
        self.analysis_systems = None
        self.network_infrastructure = None

class Analysis(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.AnalysisType
    _namespace = maec.package._namespace

    id = cybox.TypedField("id")
    method = cybox.TypedField("method")
    type = cybox.TypedField("type")
    ordinal_position = cybox.TypedField("ordinal_position")
    start_datetime = cybox.TypedField("start_datetime")
    complete_datetime = cybox.TypedField("complete_datetime")
    lastupdate_datetime = cybox.TypedField("lastupdate_datetime")
    source = cybox.TypedField("source", Source)
    analysts = cybox.TypedField("analysts", Personnel)
    summary = cybox.TypedField("summary", StructuredText)
    comments = cybox.TypedField("comments", CommentList)
    findings_bundle_reference = cybox.TypedField("findings_bundle_reference", BundleReference, multiple = True)
    tools = cybox.TypedField("tools", ToolList)
    dynamic_analysis_metadata = cybox.TypedField("dynamic_analysis_metadata", DynamicAnalysisMetadata)
    analysis_environment = cybox.TypedField("analysis_environment", AnalysisEnvironment)
    report = cybox.TypedField("report", StructuredText)

    def __init__(self, id = None, method = None, type = None, findings_bundle_reference = []):
        super(Analysis, self).__init__()
        if id:
            self.id = id
        else:
            self.id = maec.utils.idgen.create_id(prefix="analysis")
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
    # set the findings_bundle_reference values; accepts a list of bundle ID values
    def set_findings_bundle(self, bundle_id):
        self.findings_bundle_reference = [BundleReference.from_dict({'bundle_idref' : bundle_id})]
   
   # add a tool to this Anaysis's ToolList
    def add_tool(self, tool):
        self.tools.append(tool)



    





