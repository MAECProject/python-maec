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

    name = maec.TypedField("Name")
    method = maec.TypedField("Method")
    reference = maec.TypedField("Reference")
    organization = maec.TypedField("Organization")
    url = maec.TypedField("URL")
    
    def __init__(self):
        super(Source, self).__init__()

class Comment(StructuredText):
    _binding = package_binding
    _binding_class = package_binding.CommentType
    _namespace = maec.package._namespace

    author = maec.TypedField("author")
    timestamp = maec.TypedField("timestamp")
    observation_name = maec.TypedField("observation_name")

    def __init__(self):
        super(Comment, self).__init__()

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

    command_line = maec.TypedField("Command_Line")
    analysis_duration = maec.TypedField("Analysis_Duration")
    exit_code = maec.TypedField("Exit_Code")
    #raised_exception = maec.TypedField("Raised_Exception", MalwareException)
    
    def __init__(self):
        super(DynamicAnalysisMetadata, self).__init__()

class HypervisorHostSystem(System):
    _binding = package_binding
    _binding_class = package_binding.HypervisorHostSystemType
    _namespace = maec.package._namespace

    vm_hypervisor = maec.TypedField("VM_Hypervisor", PlatformSpecification)

    def __init__(self):
        super(HypervisorHostSystem, self).__init__()
        
class InstalledPrograms(maec.EntityList):
    _contained_type = PlatformSpecification
    _binding_class = package_binding.InstalledProgramsType
    _binding_var = "Program"
    _namespace = maec.package._namespace
        
class AnalysisSystem(System):
    _binding = package_binding
    _binding_class = package_binding.AnalysisSystemType
    _namespace = maec.package._namespace

    installed_programs = maec.TypedField("Installed_Programs", InstalledPrograms)

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

    layer7_protocol = maec.TypedField("layer7_protocol")
    layer4_protocol = maec.TypedField("layer4_protocol")
    port_number = maec.TypedField("port_number")
    interaction_level = maec.TypedField("interaction_level")

    def __init__(self):
        super(CapturedProtocol, self).__init__()

class CapturedProtocolList(maec.EntityList):
    _contained_type = CapturedProtocol
    _binding_class = package_binding.CapturedProtocolListType
    _binding_var = "Protocol"
    _namespace = maec.package._namespace

class NetworkInfrastructure(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.NetworkInfrastructureType
    _namespace = maec.package._namespace

    captured_protocols = maec.TypedField("Captured_Protocols", CapturedProtocolList)

    def __init__(self):
        super(NetworkInfrastructure, self).__init__()
        self.captured_protocols = CapturedProtocolList()

class AnalysisEnvironment(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.AnalysisEnvironmentType
    _namespace = maec.package._namespace

    hypervisor_host_system = maec.TypedField("Hypervisor_Host_System", HypervisorHostSystem)
    analysis_systems = maec.TypedField("Analysis_Systems", AnalysisSystemList)
    network_infrastructure = maec.TypedField("Network_Infrastructure", NetworkInfrastructure)

    def __init__(self):
        super(AnalysisEnvironment, self).__init__()

class Analysis(maec.Entity):
    _binding = package_binding
    _binding_class = package_binding.AnalysisType
    _namespace = maec.package._namespace

    id_ = maec.TypedField("id")
    method = maec.TypedField("method")
    type_ = maec.TypedField("type")
    ordinal_position = maec.TypedField("ordinal_position")
    start_datetime = maec.TypedField("start_datetime")
    complete_datetime = maec.TypedField("complete_datetime")
    lastupdate_datetime = maec.TypedField("lastupdate_datetime")
    source = maec.TypedField("Source", Source)
    analysts = maec.TypedField("Analysts", Personnel)
    summary = maec.TypedField("Summary", StructuredText)
    comments = maec.TypedField("Comments", CommentList)
    findings_bundle_reference = maec.TypedField("Findings_Bundle_Reference", BundleReference, multiple = True)
    tools = maec.TypedField("Tools", ToolList)
    dynamic_analysis_metadata = maec.TypedField("Dynamic_Analysis_Metadata", DynamicAnalysisMetadata)
    analysis_environment = maec.TypedField("Analysis_Environment", AnalysisEnvironment)
    report = maec.TypedField("Report", StructuredText)

    def __init__(self, id = None, method = None, type = None, findings_bundle_reference = []):
        super(Analysis, self).__init__()
        if id:
            self.id_ = id
        else:
            self.id_ = maec.utils.idgen.create_id(prefix="analysis")
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



    





