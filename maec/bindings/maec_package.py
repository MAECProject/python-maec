# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys

from mixbox.binding_utils import *

from maec.bindings import maec_bundle as maec_bundle_schema
from maec.bindings import mmdef_1_2 as metadatasharing
from cybox.bindings import cybox_core
from cybox.bindings import system_object
from cybox.bindings import cybox_common
from cybox.bindings import file_object
from cybox.bindings import uri_object

class AnalysisEnvironmentType(GeneratedsSuper):
    """The AnalysisEnvironmentType provides mechanisms for characterizing
    the particular hardware/software environment used in the
    analysis of a Malware Subject."""
    subclass = None
    superclass = None
    def __init__(self, Hypervisor_Host_System=None, Analysis_Systems=None, Network_Infrastructure=None):
        self.Hypervisor_Host_System = Hypervisor_Host_System
        self.Analysis_Systems = Analysis_Systems
        self.Network_Infrastructure = Network_Infrastructure
    def factory(*args_, **kwargs_):
        if AnalysisEnvironmentType.subclass:
            return AnalysisEnvironmentType.subclass(*args_, **kwargs_)
        else:
            return AnalysisEnvironmentType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Hypervisor_Host_System(self): return self.Hypervisor_Host_System
    def set_Hypervisor_Host_System(self, Hypervisor_Host_System): self.Hypervisor_Host_System = Hypervisor_Host_System
    def get_Analysis_Systems(self): return self.Analysis_Systems
    def set_Analysis_Systems(self, Analysis_Systems): self.Analysis_Systems = Analysis_Systems
    def get_Network_Infrastructure(self): return self.Network_Infrastructure
    def set_Network_Infrastructure(self, Network_Infrastructure): self.Network_Infrastructure = Network_Infrastructure
    def hasContent_(self):
        if (
            self.Hypervisor_Host_System is not None or
            self.Analysis_Systems is not None or
            self.Network_Infrastructure is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='AnalysisEnvironmentType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AnalysisEnvironmentType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='AnalysisEnvironmentType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='AnalysisEnvironmentType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Hypervisor_Host_System is not None:
            self.Hypervisor_Host_System.export(write, level, 'maecPackage:', name_='Hypervisor_Host_System', pretty_print=pretty_print)
        if self.Analysis_Systems is not None:
            self.Analysis_Systems.export(write, level, 'maecPackage:', name_='Analysis_Systems', pretty_print=pretty_print)
        if self.Network_Infrastructure is not None:
            self.Network_Infrastructure.export(write, level, 'maecPackage:', name_='Network_Infrastructure', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Hypervisor_Host_System':
            obj_ = HypervisorHostSystemType.factory()
            obj_.build(child_)
            self.set_Hypervisor_Host_System(obj_)
        elif nodeName_ == 'Analysis_Systems':
            obj_ = AnalysisSystemListType.factory()
            obj_.build(child_)
            self.set_Analysis_Systems(obj_)
        elif nodeName_ == 'Network_Infrastructure':
            obj_ = NetworkInfrastructureType.factory()
            obj_.build(child_)
            self.set_Network_Infrastructure(obj_)
# end class AnalysisEnvironmentType

class SourceType(GeneratedsSuper):
    """The SourceType provides a way of characterizing the external source
    of a relevant MAEC entity, such as an Analysis."""
    subclass = None
    superclass = None
    def __init__(self, Name=None, Method=None, Reference=None, Organization=None, URL=None):
        self.Name = Name
        self.Method = Method
        self.Reference = Reference
        self.Organization = Organization
        self.URL = URL
    def factory(*args_, **kwargs_):
        if SourceType.subclass:
            return SourceType.subclass(*args_, **kwargs_)
        else:
            return SourceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Name(self): return self.Name
    def set_Name(self, Name): self.Name = Name
    def get_Method(self): return self.Method
    def set_Method(self, Method): self.Method = Method
    def get_Reference(self): return self.Reference
    def set_Reference(self, Reference): self.Reference = Reference
    def get_Organization(self): return self.Organization
    def set_Organization(self, Organization): self.Organization = Organization
    def get_URL(self): return self.URL
    def set_URL(self, URL): self.URL = URL
    def hasContent_(self):
        if (
            self.Name is not None or
            self.Method is not None or
            self.Reference is not None or
            self.Organization is not None or
            self.URL is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='SourceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='SourceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='SourceType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='SourceType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Name is not None:
            showIndent(write, level, pretty_print)
            write('<%sName>%s</%sName>%s' % ('maecPackage:', quote_xml(self.Name), 'maecPackage:', eol_))
        if self.Method is not None:
            showIndent(write, level, pretty_print)
            write('<%sMethod>%s</%sMethod>%s' % ('maecPackage:', quote_xml(self.Method), 'maecPackage:', eol_))
        if self.Reference is not None:
            showIndent(write, level, pretty_print)
            write('<%sReference>%s</%sReference>%s' % ('maecPackage:', quote_xml(self.Reference), 'maecPackage:', eol_))
        if self.Organization is not None:
            showIndent(write, level, pretty_print)
            write('<%sOrganization>%s</%sOrganization>%s' % ('maecPackage:', quote_xml(self.Organization), 'maecPackage:', eol_))
        if self.URL is not None:
            showIndent(write, level, pretty_print)
            write('<%sURL>%s</%sURL>%s' % ('maecPackage:', quote_xml(self.URL), 'maecPackage:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Name':
            Name_ = child_.text
            Name_ = self.gds_validate_string(Name_, node, 'Name')
            self.Name = Name_
        elif nodeName_ == 'Method':
            Method_ = child_.text
            Method_ = self.gds_validate_string(Method_, node, 'Method')
            self.Method = Method_
        elif nodeName_ == 'Reference':
            Reference_ = child_.text
            Reference_ = self.gds_validate_string(Reference_, node, 'Reference')
            self.Reference = Reference_
        elif nodeName_ == 'Organization':
            Organization_ = child_.text
            Organization_ = self.gds_validate_string(Organization_, node, 'Organization')
            self.Organization = Organization_
        elif nodeName_ == 'URL':
            URL_ = child_.text
            URL_ = self.gds_validate_string(URL_, node, 'URL')
            self.URL = URL_
# end class SourceType

class CommentListType(GeneratedsSuper):
    """The CommentListType provides a simple way of capturing any comments
    relating to MAEC entities, such as Analyses."""
    subclass = None
    superclass = None
    def __init__(self, Comment=None):
        if Comment is None:
            self.Comment = []
        else:
            self.Comment = Comment
    def factory(*args_, **kwargs_):
        if CommentListType.subclass:
            return CommentListType.subclass(*args_, **kwargs_)
        else:
            return CommentListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Comment(self): return self.Comment
    def set_Comment(self, Comment): self.Comment = Comment
    def add_Comment(self, value): self.Comment.append(value)
    def insert_Comment(self, index, value): self.Comment[index] = value
    def hasContent_(self):
        if (
            self.Comment
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='CommentListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CommentListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='CommentListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='CommentListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Comment_ in self.Comment:
            Comment_.export(write, level, 'maecPackage:', name_='Comment', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Comment':
            obj_ = CommentType.factory()
            obj_.build(child_)
            self.Comment.append(obj_)
# end class CommentListType

class AnalysisSystemListType(GeneratedsSuper):
    """The AnalysisSystemListType captures a list of the systems, physical
    or virtual, used in the analysis of a Malware Subject."""
    subclass = None
    superclass = None
    def __init__(self, Analysis_System=None):
        if Analysis_System is None:
            self.Analysis_System = []
        else:
            self.Analysis_System = Analysis_System
    def factory(*args_, **kwargs_):
        if AnalysisSystemListType.subclass:
            return AnalysisSystemListType.subclass(*args_, **kwargs_)
        else:
            return AnalysisSystemListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Analysis_System(self): return self.Analysis_System
    def set_Analysis_System(self, Analysis_System): self.Analysis_System = Analysis_System
    def add_Analysis_System(self, value): self.Analysis_System.append(value)
    def insert_Analysis_System(self, index, value): self.Analysis_System[index] = value
    def hasContent_(self):
        if (
            self.Analysis_System
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='AnalysisSystemListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AnalysisSystemListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='AnalysisSystemListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='AnalysisSystemListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Analysis_System_ in self.Analysis_System:
            Analysis_System_.export(write, level, 'maecPackage:', name_='Analysis_System', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Analysis_System':
            obj_ = AnalysisSystemType.factory()
            obj_.build(child_)
            self.Analysis_System.append(obj_)
# end class AnalysisSystemListType

class ToolListType(GeneratedsSuper):
    """The ToolsType characterizes one or more tools, such as those used in
    the analysis of a Malware Subject."""
    subclass = None
    superclass = None
    def __init__(self, Tool=None):
        if Tool is None:
            self.Tool = []
        else:
            self.Tool = Tool
    def factory(*args_, **kwargs_):
        if ToolListType.subclass:
            return ToolListType.subclass(*args_, **kwargs_)
        else:
            return ToolListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Tool(self): return self.Tool
    def set_Tool(self, Tool): self.Tool = Tool
    def add_Tool(self, value): self.Tool.append(value)
    def insert_Tool(self, index, value): self.Tool[index] = value
    def hasContent_(self):
        if (
            self.Tool
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ToolListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ToolListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ToolListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ToolListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Tool_ in self.Tool:
            Tool_.export(write, level, 'maecPackage:', name_='Tool', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Tool':
            obj_ = cybox_common.ToolInformationType.factory()
            obj_.build(child_)
            self.add_Tool(obj_)
# end class ToolListType

class DynamicAnalysisMetadataType(GeneratedsSuper):
    """The DynamicAnalysisMetadataType captures any metadata specific to
    the dynamic analysis of a malware instance."""
    subclass = None
    superclass = None
    def __init__(self, Command_Line=None, Analysis_Duration=None, Exit_Code=None):
        self.Command_Line = Command_Line
        self.Analysis_Duration = Analysis_Duration
        self.Exit_Code = Exit_Code
    def factory(*args_, **kwargs_):
        if DynamicAnalysisMetadataType.subclass:
            return DynamicAnalysisMetadataType.subclass(*args_, **kwargs_)
        else:
            return DynamicAnalysisMetadataType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Command_Line(self): return self.Command_Line
    def set_Command_Line(self, Command_Line): self.Command_Line = Command_Line
    def get_Analysis_Duration(self): return self.Analysis_Duration
    def set_Analysis_Duration(self, Analysis_Duration): self.Analysis_Duration = Analysis_Duration
    def get_Exit_Code(self): return self.Exit_Code
    def set_Exit_Code(self, Exit_Code): self.Exit_Code = Exit_Code
    def hasContent_(self):
        if (
            self.Command_Line is not None or
            self.Analysis_Duration is not None or
            self.Exit_Code is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='DynamicAnalysisMetadataType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='DynamicAnalysisMetadataType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='DynamicAnalysisMetadataType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='DynamicAnalysisMetadataType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Command_Line is not None:
            showIndent(write, level, pretty_print)
            write('<%sCommand_Line>%s</%sCommand_Line>%s' % ('maecPackage:', quote_xml(self.Command_Line), 'maecPackage:', eol_))
        if self.Analysis_Duration is not None:
            showIndent(write, level, pretty_print)
            write('<%sAnalysis_Duration>%s</%sAnalysis_Duration>%s' % ('maecPackage:', self.gds_format_float(self.Analysis_Duration, input_name='Analysis_Duration'), 'maecPackage:', eol_))
        if self.Exit_Code is not None:
            showIndent(write, level, pretty_print)
            write('<%sExit_Code>%s</%sExit_Code>%s' % ('maecPackage:', self.gds_format_integer(self.Exit_Code, input_name='Exit_Code'), 'maecPackage:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Command_Line':
            Command_Line_ = child_.text
            Command_Line_ = self.gds_validate_string(Command_Line_, node, 'Command_Line')
            self.Command_Line = Command_Line_
        elif nodeName_ == 'Analysis_Duration':
            sval_ = child_.text
            try:
                fval_ = float(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires float or double: %s' % exp)
            fval_ = self.gds_validate_float(fval_, node, 'Analysis_Duration')
            self.Analysis_Duration = fval_
        elif nodeName_ == 'Exit_Code':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'Exit_Code')
            self.Exit_Code = ival_
# end class DynamicAnalysisMetadataType

class AnalysisType(GeneratedsSuper):
    """The AnalysisType provides a way of capturing the information
    associated with the analysis of a malware instance, such as the
    subject, authors, start datetime, and other relevant data.The
    required id field specifies a unique ID for this Analysis. The
    ID must follow the pattern defined in the AnalysisIDPattern
    simple type.The type field specifies the type of malware
    analysis being performed.The method field specifies the analysis
    method used in the analysis. The ordinal_position field
    specifies the ordering of the analysis with respect to the other
    analyses performed on the Malware Subject.The start_datetime
    field specifies the date/time the analysis was started.The
    complete_datetime field specifies the date/time the analysis was
    completed.The lastupdate_datetime field specifies the date/time
    the analysis was last updated."""
    subclass = None
    superclass = None
    def __init__(self, start_datetime=None, complete_datetime=None, method=None, ordinal_position=None, lastupdate_datetime=None, type=None, id=None, Source=None, Analysts=None, Summary=None, Comments=None, Findings_Bundle_Reference=None, Tools=None, Dynamic_Analysis_Metadata=None, Analysis_Environment=None, Report=None):
        self.start_datetime = _cast(None, start_datetime)
        self.complete_datetime = _cast(None, complete_datetime)
        self.method = _cast(None, method)
        self.ordinal_position = _cast(int, ordinal_position)
        self.lastupdate_datetime = _cast(None, lastupdate_datetime)
        self.type = _cast(None, type)
        self.id = _cast(None, id)
        self.Source = Source
        self.Analysts = Analysts
        self.Summary = Summary
        self.Comments = Comments
        if Findings_Bundle_Reference is None:
            self.Findings_Bundle_Reference = []
        else:
            self.Findings_Bundle_Reference = Findings_Bundle_Reference
        self.Tools = Tools
        self.Dynamic_Analysis_Metadata = Dynamic_Analysis_Metadata
        self.Analysis_Environment = Analysis_Environment
        self.Report = Report
    def factory(*args_, **kwargs_):
        if AnalysisType.subclass:
            return AnalysisType.subclass(*args_, **kwargs_)
        else:
            return AnalysisType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Source(self): return self.Source
    def set_Source(self, Source): self.Source = Source
    def get_Analysts(self): return self.Analysts
    def set_Analysts(self, Analysts): self.Analysts = Analysts
    def get_Summary(self): return self.Summary
    def set_Summary(self, Summary): self.Summary = Summary
    def get_Comments(self): return self.Comments
    def set_Comments(self, Comments): self.Comments = Comments
    def get_Findings_Bundle_Reference(self): return self.Findings_Bundle_Reference
    def set_Findings_Bundle_Reference(self, Findings_Bundle_Reference): self.Findings_Bundle_Reference = Findings_Bundle_Reference
    def add_Findings_Bundle_Reference(self, value): self.Findings_Bundle_Reference.append(value)
    def insert_Findings_Bundle_Reference(self, index, value): self.Findings_Bundle_Reference[index] = value
    def get_Tools(self): return self.Tools
    def set_Tools(self, Tools): self.Tools = Tools
    def get_Dynamic_Analysis_Metadata(self): return self.Dynamic_Analysis_Metadata
    def set_Dynamic_Analysis_Metadata(self, Dynamic_Analysis_Metadata): self.Dynamic_Analysis_Metadata = Dynamic_Analysis_Metadata
    def get_Analysis_Environment(self): return self.Analysis_Environment
    def set_Analysis_Environment(self, Analysis_Environment): self.Analysis_Environment = Analysis_Environment
    def get_Report(self): return self.Report
    def set_Report(self, Report): self.Report = Report
    def get_start_datetime(self): return self.start_datetime
    def set_start_datetime(self, start_datetime): self.start_datetime = start_datetime
    def get_complete_datetime(self): return self.complete_datetime
    def set_complete_datetime(self, complete_datetime): self.complete_datetime = complete_datetime
    def get_method(self): return self.method
    def set_method(self, method): self.method = method
    def get_ordinal_position(self): return self.ordinal_position
    def set_ordinal_position(self, ordinal_position): self.ordinal_position = ordinal_position
    def get_lastupdate_datetime(self): return self.lastupdate_datetime
    def set_lastupdate_datetime(self, lastupdate_datetime): self.lastupdate_datetime = lastupdate_datetime
    def get_type(self): return self.type
    def set_type(self, type): self.type = type
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Source is not None or
            self.Analysts is not None or
            self.Summary is not None or
            self.Comments is not None or
            self.Findings_Bundle_Reference is not None or
            self.Tools is not None or
            self.Dynamic_Analysis_Metadata is not None or
            self.Analysis_Environment is not None or
            self.Report is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='AnalysisType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AnalysisType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='AnalysisType'):
        if self.start_datetime is not None and 'start_datetime' not in already_processed:
            already_processed.add('start_datetime')
            write(' start_datetime="%s"' % self.start_datetime)
        if self.complete_datetime is not None and 'complete_datetime' not in already_processed:
            already_processed.add('complete_datetime')
            write(' complete_datetime="%s"' % self.complete_datetime)
        if self.method is not None and 'method' not in already_processed:
            already_processed.add('method')
            write(' method=%s' % (quote_attrib(self.method), ))
        if self.ordinal_position is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            write(' ordinal_position="%s"' % self.gds_format_integer(self.ordinal_position, input_name='ordinal_position'))
        if self.lastupdate_datetime is not None and 'lastupdate_datetime' not in already_processed:
            already_processed.add('lastupdate_datetime')
            write(' lastupdate_datetime="%s"' % self.lastupdate_datetime)
        if self.type is not None and 'type' not in already_processed:
            already_processed.add('type')
            write(' type=%s' % (quote_attrib(self.type), ))
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='AnalysisType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Source is not None:
            self.Source.export(write, level, 'maecPackage:', name_='Source', pretty_print=pretty_print)
        if self.Analysts is not None:
            self.Analysts.export(write, level, 'maecPackage:', name_='Analysts', pretty_print=pretty_print)
        if self.Summary is not None:
            self.Summary.export(write, level, 'maecPackage:', name_='Summary', pretty_print=pretty_print)
        if self.Comments is not None:
            self.Comments.export(write, level, 'maecPackage:', name_='Comments', pretty_print=pretty_print)
        for Findings_Bundle_Reference_ in self.Findings_Bundle_Reference:
            Findings_Bundle_Reference_.export(write, level, 'maecPackage:', name_='Findings_Bundle_Reference', pretty_print=pretty_print)
        if self.Tools is not None:
            self.Tools.export(write, level, 'maecPackage:', name_='Tools', pretty_print=pretty_print)
        if self.Dynamic_Analysis_Metadata is not None:
            self.Dynamic_Analysis_Metadata.export(write, level, 'maecPackage:', name_='Dynamic_Analysis_Metadata', pretty_print=pretty_print)
        if self.Analysis_Environment is not None:
            self.Analysis_Environment.export(write, level, 'maecPackage:', name_='Analysis_Environment', pretty_print=pretty_print)
        if self.Report is not None:
            self.Report.export(write, level, 'maecPackage:', name_='Report', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('start_datetime', node)
        if value is not None and 'start_datetime' not in already_processed:
            already_processed.add('start_datetime')
            try:
                self.start_datetime = value
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (start_datetime): %s' % exp)
        value = find_attr_value_('complete_datetime', node)
        if value is not None and 'complete_datetime' not in already_processed:
            already_processed.add('complete_datetime')
            try:
                self.complete_datetime = value
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (complete_datetime): %s' % exp)
        value = find_attr_value_('method', node)
        if value is not None and 'method' not in already_processed:
            already_processed.add('method')
            self.method = value
        value = find_attr_value_('ordinal_position', node)
        if value is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            try:
                self.ordinal_position = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
            if self.ordinal_position <= 0:
                raise_parse_error(node, 'Invalid PositiveInteger')
        value = find_attr_value_('lastupdate_datetime', node)
        if value is not None and 'lastupdate_datetime' not in already_processed:
            already_processed.add('lastupdate_datetime')
            try:
                self.lastupdate_datetime = value
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (lastupdate_datetime): %s' % exp)
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.add('type')
            self.type = value
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Source':
            obj_ = SourceType.factory()
            obj_.build(child_)
            self.set_Source(obj_)
        elif nodeName_ == 'Analysts':
            obj_ = cybox_common.PersonnelType.factory()
            obj_.build(child_)
            self.set_Analysts(obj_)
        elif nodeName_ == 'Summary':
            obj_ = cybox_common.StructuredTextType.factory()
            obj_.build(child_)
            self.set_Summary(obj_)
        elif nodeName_ == 'Comments':
            obj_ = CommentListType.factory()
            obj_.build(child_)
            self.set_Comments(obj_)
        elif nodeName_ == 'Findings_Bundle_Reference':
            obj_ = maec_bundle_schema.BundleReferenceType.factory()
            obj_.build(child_)
            self.Findings_Bundle_Reference.append(obj_)
        elif nodeName_ == 'Tools':
            obj_ = ToolListType.factory()
            obj_.build(child_)
            self.set_Tools(obj_)
        elif nodeName_ == 'Dynamic_Analysis_Metadata':
            obj_ = DynamicAnalysisMetadataType.factory()
            obj_.build(child_)
            self.set_Dynamic_Analysis_Metadata(obj_)
        elif nodeName_ == 'Analysis_Environment':
            obj_ = AnalysisEnvironmentType.factory()
            obj_.build(child_)
            self.set_Analysis_Environment(obj_)
        elif nodeName_ == 'Report':
            obj_ = cybox_common.StructuredTextType.factory()
            obj_.build(child_)
            self.set_Report(obj_)
# end class AnalysisType

class AnalysisListType(GeneratedsSuper):
    """The AnalysisListType captures a list of analyses that were performed
    on a Malware Subject."""
    subclass = None
    superclass = None
    def __init__(self, Analysis=None):
        if Analysis is None:
            self.Analysis = []
        else:
            self.Analysis = Analysis
    def factory(*args_, **kwargs_):
        if AnalysisListType.subclass:
            return AnalysisListType.subclass(*args_, **kwargs_)
        else:
            return AnalysisListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Analysis(self): return self.Analysis
    def set_Analysis(self, Analysis): self.Analysis = Analysis
    def add_Analysis(self, value): self.Analysis.append(value)
    def insert_Analysis(self, index, value): self.Analysis[index] = value
    def hasContent_(self):
        if (
            self.Analysis
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='AnalysisListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AnalysisListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='AnalysisListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='AnalysisListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Analysis_ in self.Analysis:
            Analysis_.export(write, level, 'maecPackage:', name_='Analysis', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Analysis':
            obj_ = AnalysisType.factory()
            obj_.build(child_)
            self.Analysis.append(obj_)
# end class AnalysisListType

class InstalledProgramsType(GeneratedsSuper):
    """The InstalledProgramsType captures the programs installed on a
    particular operating system image, via a list of CPE
    identifiers."""
    subclass = None
    superclass = None
    def __init__(self, Program=None):
        if Program is None:
            self.Program = []
        else:
            self.Program = Program
    def factory(*args_, **kwargs_):
        if InstalledProgramsType.subclass:
            return InstalledProgramsType.subclass(*args_, **kwargs_)
        else:
            return InstalledProgramsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Program(self): return self.Program
    def set_Program(self, Program): self.Program = Program
    def add_Program(self, value): self.Program.append(value)
    def insert_Program(self, index, value): self.Program[index] = value
    def hasContent_(self):
        if (
            self.Program
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='InstalledProgramsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='InstalledProgramsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='InstalledProgramsType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='InstalledProgramsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Program_ in self.Program:
            Program_.export(write, level, 'maecPackage:', name_='Program', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Program':
            obj_ = cybox_common.PlatformSpecificationType.factory()
            obj_.build(child_)
            self.set_Program(obj_)
# end class InstalledProgramsType

class PackageType(GeneratedsSuper):
    """The PackageType is the namesake type of the MAEC Package schema, and
    captures either a single Malware Subject, or a collection of
    Malware Subjects that are related in some way (even if exact
    details of the metadatasharing.relationship are unknown). Unlike the MAEC
    Bundle, which captures only the MAEC-characterized analysis
    results for a malware instance, the Package permits the capture
    of additional metadata relating to the analysis, relationships
    between Malware Subjects, and similar types of entities.The
    required id field specifies a unique ID for this Package. The ID
    must follow the pattern defined in the PackageIDPattern simple
    type.The required schema_version field specifies the version of
    the MAEC Package schema that the document has been written in
    and that should be used for validation.The timestamp field
    specifies the date/time that the Package was generated."""
    subclass = None
    superclass = None
    def __init__(self, timestamp=None, id=None, schema_version=None, Malware_Subjects=None, Grouping_Relationships=None):
        self.timestamp = _cast(None, timestamp)
        self.id = _cast(None, id)
        self.schema_version = schema_version
        self.Malware_Subjects = Malware_Subjects
        self.Grouping_Relationships = Grouping_Relationships
    def factory(*args_, **kwargs_):
        if PackageType.subclass:
            return PackageType.subclass(*args_, **kwargs_)
        else:
            return PackageType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Malware_Subjects(self): return self.Malware_Subjects
    def set_Malware_Subjects(self, Malware_Subjects): self.Malware_Subjects = Malware_Subjects
    def get_Grouping_Relationships(self): return self.Grouping_Relationships
    def set_Grouping_Relationships(self, Grouping_Relationships): self.Grouping_Relationships = Grouping_Relationships
    def get_timestamp(self): return self.timestamp
    def set_timestamp(self, timestamp): self.timestamp = timestamp
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def get_schema_version(self): return self.schema_version
    def set_schema_version(self, schema_version): self.schema_version = schema_version
    def hasContent_(self):
        if (
            self.Malware_Subjects is not None or
            self.Grouping_Relationships is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MAEC_Package', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MAEC_Package')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MAEC_Package'):
        if self.timestamp is not None and 'timestamp' not in already_processed:
            already_processed.add('timestamp')
            write(' timestamp="%s"' % self.timestamp)
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
        if self.schema_version is not None and 'schema_version' not in already_processed:
            already_processed.add('schema_version')
            write(' schema_version="%s"' % self.schema_version)
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MAEC_Package', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Malware_Subjects is not None:
            self.Malware_Subjects.export(write, level, 'maecPackage:', name_='Malware_Subjects', pretty_print=pretty_print)
        if self.Grouping_Relationships is not None:
            self.Grouping_Relationships.export(write, level, 'maecPackage:', name_='Grouping_Relationships', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('timestamp', node)
        if value is not None and 'timestamp' not in already_processed:
            already_processed.add('timestamp')
            try:
                self.timestamp = value
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (timestamp): %s' % exp)
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
        value = find_attr_value_('schema_version', node)
        if value is not None and 'schema_version' not in already_processed:
            already_processed.add('schema_version')
            self.schema_version = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Malware_Subjects':
            obj_ = MalwareSubjectListType.factory()
            obj_.build(child_)
            self.set_Malware_Subjects(obj_)
        elif nodeName_ == 'Grouping_Relationships':
            obj_ = GroupingRelationshipListType.factory()
            obj_.build(child_)
            self.set_Grouping_Relationships(obj_)
# end class PackageType

class MalwareSubjectType(GeneratedsSuper):
    """The MalwareSubjectType captures all of the details pertaining to a
    single malware instance, including any corresponding Analyses,
    Field Data, Findings Bundles, and relationships to other Malware
    Subjects.The required id field specifies a unique ID for this
    Malware Subject. The ID must follow the pattern defined in the
    MalwareSubjectIDPattern simple type."""
    subclass = None
    superclass = None
    def __init__(self, id=None, Malware_Instance_Object_Attributes=None, Label=None, Configuration_Details=None, Minor_Variants=None, Development_Environment=None, Field_Data=None, Analyses=None, Findings_Bundles=None, Relationships=None, Compatible_Platform=None):
        self.id = _cast(None, id)
        self.Malware_Instance_Object_Attributes = Malware_Instance_Object_Attributes
        self.Configuration_Details = Configuration_Details
        self.Minor_Variants = Minor_Variants
        self.Development_Environment = Development_Environment 
        self.Field_Data = Field_Data
        self.Analyses = Analyses
        self.Findings_Bundles = Findings_Bundles
        self.Relationships = Relationships
        if Label is None:
            self.Label = []
        else:
            self.Label = Label
        if Compatible_Platform is None:
            self.Compatible_Platform = []
        else:
            self.Compatible_Platform = Compatible_Platform
    def factory(*args_, **kwargs_):
        if MalwareSubjectType.subclass:
            return MalwareSubjectType.subclass(*args_, **kwargs_)
        else:
            return MalwareSubjectType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Malware_Instance_Object_Attributes(self): return self.Malware_Instance_Object_Attributes
    def set_Malware_Instance_Object_Attributes(self, Malware_Instance_Object_Attributes): self.Malware_Instance_Object_Attributes = Malware_Instance_Object_Attributes
    def get_Configuration_Details(self): return self.Configuration_Details
    def set_Configuration_Details(self, Configuration_Details): self.Configuration_Details = Configuration_Details
    def get_Label(self): return self.Label
    def set_Label(self, Label): self.Label = Label
    def add_Label(self, value): self.Label.append(value)
    def insert_Label(self, index, value): self.Label[index] = value
    def get_Minor_Variants(self): return self.Minor_Variants
    def set_Minor_Variants(self, Minor_Variants): self.Minor_Variants = Minor_Variants
    def get_Development_Environment(self): return self.Development_Environment
    def set_Development_Environment(self, Development_Environment): self.Development_Environment = Development_Environment
    def get_Field_Data(self): return self.Field_Data
    def set_Field_Data(self, Field_Data): self.Field_Data = Field_Data
    def get_Analyses(self): return self.Analyses
    def set_Analyses(self, Analyses): self.Analyses = Analyses
    def get_Findings_Bundles(self): return self.Findings_Bundles
    def set_Findings_Bundles(self, Findings_Bundles): self.Findings_Bundles = Findings_Bundles
    def get_Relationships(self): return self.Relationships
    def set_Relationships(self, Relationships): self.Relationships = Relationships
    def get_Compatible_Platform(self): return self.Compatible_Platform
    def set_Compatible_Platform(self, Compatible_Platform): self.Compatible_Platform = Compatible_Platform
    def add_Compatible_Platform(self, value): self.Compatible_Platform.append(value)
    def insert_Compatible_Platform(self, index, value): self.Compatible_Platform[index] = value
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Malware_Instance_Object_Attributes is not None or
            self.Label is not None or
            self.Configuration_Details is not None or
            self.Minor_Variants is not None or
            self.Development_Environment is not None or
            self.Field_Data is not None or
            self.Analyses is not None or
            self.Findings_Bundles is not None or
            self.Relationships is not None or
            self.Compatible_Platform is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareSubjectType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareSubjectType'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Malware_Instance_Object_Attributes is not None:
            self.Malware_Instance_Object_Attributes.export(write, level, 'maecPackage:', name_='Malware_Instance_Object_Attributes', pretty_print=pretty_print)
        for Label_ in self.Label:
            Label_.export(write, level, 'maecPackage:', name_='Label', pretty_print=pretty_print)
        if self.Configuration_Details is not None:
            self.Configuration_Details.export(write, level, 'maecPackage:', name_='Configuration_Details', pretty_print=pretty_print)
        if self.Minor_Variants is not None:
            self.Minor_Variants.export(write, level, 'maecPackage:', name_='Minor_Variants', pretty_print=pretty_print)
        if self.Development_Environment is not None:
            self.Development_Environment.export(write, level, 'maecPackage:', name_='Development_Environment', pretty_print=pretty_print)
        if self.Field_Data is not None:
            self.Field_Data.export(write, level, 'maecPackage:', name_='Field_Data', pretty_print=pretty_print)
        if self.Analyses is not None:
            self.Analyses.export(write, level, 'maecPackage:', name_='Analyses', pretty_print=pretty_print)
        if self.Findings_Bundles is not None:
            self.Findings_Bundles.export(write, level, 'maecPackage:', name_='Findings_Bundles', pretty_print=pretty_print)
        if self.Relationships is not None:
            self.Relationships.export(write, level, 'maecPackage:', name_='Relationships', pretty_print=pretty_print)
        for Compatible_Platform_ in self.Compatible_Platform:
            Compatible_Platform_.export(write, level, 'maecPackage:', name_='Compatible_Platform', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Malware_Instance_Object_Attributes':
            obj_ = cybox_core.ObjectType.factory()
            obj_.build(child_)
            self.set_Malware_Instance_Object_Attributes(obj_)
        elif nodeName_ == 'Label':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.Label.append(obj_)
        elif nodeName_ == 'Configuration_Details':
            obj_ = MalwareConfigurationDetailsType.factory()
            obj_.build(child_)
            self.set_Configuration_Details(obj_)
        elif nodeName_ == 'Minor_Variants':
            obj_ = MinorVariantListType.factory()
            obj_.build(child_)
            self.set_Minor_Variants(obj_)
        elif nodeName_ == 'Development_Environment':
            obj_ = MalwareDevelopmentEnvironmentType.factory()
            obj_.build(child_)
            self.set_Development_Environment(obj_)
        elif nodeName_ == 'Field_Data':
            obj_ = metadatasharing.fieldDataEntry.factory()
            obj_.build(child_)
            self.set_Field_Data(obj_)
        elif nodeName_ == 'Analyses':
            obj_ = AnalysisListType.factory()
            obj_.build(child_)
            self.set_Analyses(obj_)
        elif nodeName_ == 'Findings_Bundles':
            obj_ = FindingsBundleListType.factory()
            obj_.build(child_)
            self.set_Findings_Bundles(obj_)
        elif nodeName_ == 'Relationships':
            obj_ = MalwareSubjectRelationshipListType.factory()
            obj_.build(child_)
            self.set_Relationships(obj_)
        elif nodeName_ == 'Compatible_Platform':
            obj_ = cybox_common.PlatformSpecificationType.factory()
            obj_.build(child_)
            self.Compatible_Platform.append(obj_)
# end class MalwareSubjectType

class MetaAnalysisType(GeneratedsSuper):
    """The MetaAnalysisType captures meta-analysis entities associated with
    the Bundles that were captured for a Malware Subject, such as
    Action Equivalencies."""
    subclass = None
    superclass = None
    def __init__(self, Action_Equivalences=None, Object_Equivalences=None):
        self.Action_Equivalences = Action_Equivalences
        self.Object_Equivalences = Object_Equivalences
    def factory(*args_, **kwargs_):
        if MetaAnalysisType.subclass:
            return MetaAnalysisType.subclass(*args_, **kwargs_)
        else:
            return MetaAnalysisType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action_Equivalences(self): return self.Action_Equivalences
    def set_Action_Equivalences(self, Action_Equivalences): self.Action_Equivalences = Action_Equivalences
    def get_Object_Equivalences(self): return self.Object_Equivalences
    def set_Object_Equivalences(self, Object_Equivalences): self.Object_Equivalences = Object_Equivalences
    def hasContent_(self):
        if (
            self.Action_Equivalences is not None or
            self.Object_Equivalences is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MetaAnalysisType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MetaAnalysisType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MetaAnalysisType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MetaAnalysisType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Action_Equivalences is not None:
            self.Action_Equivalences.export(write, level, 'maecPackage:', name_='Action_Equivalences', pretty_print=pretty_print)
        if self.Object_Equivalences is not None:
            self.Object_Equivalences.export(write, level, 'maecPackage:', name_='Object_Equivalences', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action_Equivalences':
            obj_ = ActionEquivalenceListType.factory()
            obj_.build(child_)
            self.set_Action_Equivalences(obj_)
        elif nodeName_ == 'Object_Equivalences':
            obj_ = ObjectEquivalenceListType.factory()
            obj_.build(child_)
            self.set_Object_Equivalences(obj_)
# end class MetaAnalysisType

class MalwareSubjectRelationshipType(GeneratedsSuper):
    """The MalwareSubjectRelationshipType provides a mechanism for
    capturing the relationships between a Malware Subject and one or
    more other Malware Subjects."""
    subclass = None
    superclass = None
    def __init__(self, Type=None, Malware_Subject_Reference=None):
        self.Type = Type
        if Malware_Subject_Reference is None:
            self.Malware_Subject_Reference = []
        else:
            self.Malware_Subject_Reference = Malware_Subject_Reference
    def factory(*args_, **kwargs_):
        if MalwareSubjectRelationshipType.subclass:
            return MalwareSubjectRelationshipType.subclass(*args_, **kwargs_)
        else:
            return MalwareSubjectRelationshipType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Type(self): return self.Type
    def set_Type(self, Type): self.Type = Type
    def get_Malware_Subject_Reference(self): return self.Malware_Subject_Reference
    def set_Malware_Subject_Reference(self, Malware_Subject_Reference): self.Malware_Subject_Reference = Malware_Subject_Reference
    def add_Malware_Subject_Reference(self, value): self.Malware_Subject_Reference.append(value)
    def insert_Malware_Subject_Reference(self, index, value): self.Malware_Subject_Reference[index] = value
    def hasContent_(self):
        if (
            self.Type is not None or
            self.Malware_Subject_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectRelationshipType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareSubjectRelationshipType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareSubjectRelationshipType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectRelationshipType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Type is not None:
            self.Type.export(write, level, 'maecPackage:', name_='Type', pretty_print=pretty_print)
        for Malware_Subject_Reference_ in self.Malware_Subject_Reference:
            Malware_Subject_Reference_.export(write, level, 'maecPackage:', name_='Malware_Subject_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Type':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Type(obj_)
        elif nodeName_ == 'Malware_Subject_Reference':
            obj_ = MalwareSubjectReferenceType.factory()
            obj_.build(child_)
            self.Malware_Subject_Reference.append(obj_)
# end class MalwareSubjectRelationshipType

class MalwareSubjectRelationshipListType(GeneratedsSuper):
    """The MalwareSubjectRelationshipListType captures a list of
    relationships between a Malware Subject and other Malware
    Subjects."""
    subclass = None
    superclass = None
    def __init__(self, Relationship=None):
        if Relationship is None:
            self.Relationship = []
        else:
            self.Relationship = Relationship
    def factory(*args_, **kwargs_):
        if MalwareSubjectRelationshipListType.subclass:
            return MalwareSubjectRelationshipListType.subclass(*args_, **kwargs_)
        else:
            return MalwareSubjectRelationshipListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Relationship(self): return self.Relationship
    def set_Relationship(self, Relationship): self.Relationship = Relationship
    def add_Relationship(self, value): self.Relationship.append(value)
    def insert_Relationship(self, index, value): self.Relationship[index] = value
    def hasContent_(self):
        if (
            self.Relationship
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectRelationshipListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareSubjectRelationshipListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareSubjectRelationshipListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectRelationshipListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Relationship_ in self.Relationship:
            Relationship_.export(write, level, 'maecPackage:', name_='Relationship', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Relationship':
            obj_ = MalwareSubjectRelationshipType.factory()
            obj_.build(child_)
            self.Relationship.append(obj_)
# end class MalwareSubjectRelationshipListType

class MalwareSubjectReferenceType(GeneratedsSuper):
    """The MalwareSubjectReferenceType provides a mechanism for specifying
    a metadatasharing.reference to a Malware Subject contained in the Package.The
    malware_subject_idref field provides a metadatasharing.reference to a Malware
    Subject contained in the Package, via its ID."""
    subclass = None
    superclass = None
    def __init__(self, malware_subject_idref=None):
        self.malware_subject_idref = _cast(None, malware_subject_idref)
        pass
    def factory(*args_, **kwargs_):
        if MalwareSubjectReferenceType.subclass:
            return MalwareSubjectReferenceType.subclass(*args_, **kwargs_)
        else:
            return MalwareSubjectReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_malware_subject_idref(self): return self.malware_subject_idref
    def set_malware_subject_idref(self, malware_subject_idref): self.malware_subject_idref = malware_subject_idref
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareSubjectReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareSubjectReferenceType'):
        if self.malware_subject_idref is not None and 'malware_subject_idref' not in already_processed:
            already_processed.add('malware_subject_idref')
            write(' malware_subject_idref=%s' % (quote_attrib(self.malware_subject_idref), ))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectReferenceType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('malware_subject_idref', node)
        if value is not None and 'malware_subject_idref' not in already_processed:
            already_processed.add('malware_subject_idref')
            self.malware_subject_idref = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class MalwareSubjectReferenceType

class MalwareSubjectListType(GeneratedsSuper):
    """The MalwareSubjectListType captures a list of Malware Subjects."""
    subclass = None
    superclass = None
    def __init__(self, Malware_Subject=None):
        if Malware_Subject is None:
            self.Malware_Subject = []
        else:
            self.Malware_Subject = Malware_Subject
    def factory(*args_, **kwargs_):
        if MalwareSubjectListType.subclass:
            return MalwareSubjectListType.subclass(*args_, **kwargs_)
        else:
            return MalwareSubjectListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Malware_Subject(self): return self.Malware_Subject
    def set_Malware_Subject(self, Malware_Subject): self.Malware_Subject = Malware_Subject
    def add_Malware_Subject(self, value): self.Malware_Subject.append(value)
    def insert_Malware_Subject(self, index, value): self.Malware_Subject[index] = value
    def hasContent_(self):
        if (
            self.Malware_Subject
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareSubjectListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareSubjectListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareSubjectListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Malware_Subject_ in self.Malware_Subject:
            Malware_Subject_.export(write, level, 'maecPackage:', name_='Malware_Subject', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Malware_Subject':
            obj_ = MalwareSubjectType.factory()
            obj_.build(child_)
            self.Malware_Subject.append(obj_)
# end class MalwareSubjectListType

class MinorVariantListType(GeneratedsSuper):
    """The MinorVariantListType captures a list of minor variants of a
    Malware Subject's malware instance object. For example, the same
    binary with but with different filenames."""
    subclass = None
    superclass = None
    def __init__(self, Minor_Variant=None):
        if Minor_Variant is None:
            self.Minor_Variant = []
        else:
            self.Minor_Variant = Minor_Variant
    def factory(*args_, **kwargs_):
        if MinorVariantListType.subclass:
            return MinorVariantListType.subclass(*args_, **kwargs_)
        else:
            return MinorVariantListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Minor_Variant(self): return self.Minor_Variant
    def set_Minor_Variant(self, Minor_Variant): self.Minor_Variant = Minor_Variant
    def add_Minor_Variant(self, value): self.Minor_Variant.append(value)
    def insert_Minor_Variant(self, index, value): self.Minor_Variant[index] = value
    def hasContent_(self):
        if (
            self.Minor_Variant
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MinorVariantListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MinorVariantListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MinorVariantListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MinorVariantListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Minor_Variant_ in self.Minor_Variant:
            Minor_Variant_.export(write, level, 'maecPackage:', name_='Minor_Variant', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Minor_Variant':
            obj_ = cybox_core.ObjectType.factory()
            obj_.build(child_)
            self.Minor_Variant.append(obj_)
# end class MinorVariantListType

class FindingsBundleListType(GeneratedsSuper):
    """The FindingsBundleListType captures a list of Bundles or external
    references to Bundles, along with any related meta-analysis
    entities."""
    subclass = None
    superclass = None
    def __init__(self, Meta_Analysis=None, Bundle=None, Bundle_External_Reference=None):
        self.Meta_Analysis = Meta_Analysis
        if Bundle is None:
            self.Bundle = []
        else:
            self.Bundle = Bundle
        if Bundle_External_Reference is None:
            self.Bundle_External_Reference = []
        else:
            self.Bundle_External_Reference = Bundle_External_Reference
    def factory(*args_, **kwargs_):
        if FindingsBundleListType.subclass:
            return FindingsBundleListType.subclass(*args_, **kwargs_)
        else:
            return FindingsBundleListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Meta_Analysis(self): return self.Meta_Analysis
    def set_Meta_Analysis(self, Meta_Analysis): self.Meta_Analysis = Meta_Analysis
    def get_Bundle(self): return self.Bundle
    def set_Bundle(self, Bundle): self.Bundle = Bundle
    def add_Bundle(self, value): self.Bundle.append(value)
    def insert_Bundle(self, index, value): self.Bundle[index] = value
    def get_Bundle_External_Reference(self): return self.Bundle_External_Reference
    def set_Bundle_External_Reference(self, Bundle_External_Reference): self.Bundle_External_Reference = Bundle_External_Reference
    def add_Bundle_External_Reference(self, value): self.Bundle_External_Reference.append(value)
    def insert_Bundle_External_Reference(self, index, value): self.Bundle_External_Reference[index] = value
    def hasContent_(self):
        if (
            self.Meta_Analysis is not None or
            self.Bundle or
            self.Bundle_External_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='FindingsBundleListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='FindingsBundleListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='FindingsBundleListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='FindingsBundleListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Meta_Analysis is not None:
            self.Meta_Analysis.export(write, level, 'maecPackage:', name_='Meta_Analysis', pretty_print=pretty_print)
        for Bundle_ in self.Bundle:
            Bundle_.export(write, level, 'maecPackage:', name_='Bundle', pretty_print=pretty_print)
        for Bundle_External_Reference_ in self.Bundle_External_Reference:
            showIndent(write, level, pretty_print)
            write('<%sBundle_External_Reference>%s</%sBundle_External_Reference>%s' % ('maecPackage:', self.gds_format_string(quote_xml(Bundle_External_Reference_).encode(ExternalEncoding), input_name='Bundle_External_Reference'), 'maecPackage:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Meta_Analysis':
            obj_ = MetaAnalysisType.factory()
            obj_.build(child_)
            self.set_Meta_Analysis(obj_)
        elif nodeName_ == 'Bundle':
            obj_ = maec_bundle_schema.BundleType.factory()
            obj_.build(child_)
            self.Bundle.append(obj_)
        elif nodeName_ == 'Bundle_External_Reference':
            Bundle_External_Reference_ = child_.text
            Bundle_External_Reference_ = self.gds_validate_string(Bundle_External_Reference_, node, 'Bundle_External_Reference')
            self.Bundle_External_Reference.append(Bundle_External_Reference_)
# end class FindingsBundleListType

class GroupingRelationshipType(GeneratedsSuper):
    """The GroupingRelationshipType provides a mechanism for specifying the
    metadatasharing.relationship that groups together the Malware Subjects in a
    Package."""
    subclass = None
    superclass = None
    def __init__(self, Type=None, Malware_Family_Name=None, Malware_Toolkit_Name=None, Clustering_Metadata=None):
        self.Type = Type
        self.Malware_Family_Name = Malware_Family_Name
        self.Malware_Toolkit_Name = Malware_Toolkit_Name
        self.Clustering_Metadata = Clustering_Metadata
    def factory(*args_, **kwargs_):
        if GroupingRelationshipType.subclass:
            return GroupingRelationshipType.subclass(*args_, **kwargs_)
        else:
            return GroupingRelationshipType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Type(self): return self.Type
    def set_Type(self, Type): self.Type = Type
    def get_Malware_Family_Name(self): return self.Malware_Family_Name
    def set_Malware_Family_Name(self, Malware_Family_Name): self.Malware_Family_Name = Malware_Family_Name
    def get_Malware_Toolkit_Name(self): return self.Malware_Toolkit_Name
    def set_Malware_Toolkit_Name(self, Malware_Toolkit_Name): self.Malware_Toolkit_Name = Malware_Toolkit_Name
    def get_Clustering_Metadata(self): return self.Clustering_Metadata
    def set_Clustering_Metadata(self, Clustering_Metadata): self.Clustering_Metadata = Clustering_Metadata
    def hasContent_(self):
        if (
            self.Type is not None or
            self.Malware_Family_Name is not None or
            self.Malware_Toolkit_Name is not None or
            self.Clustering_Metadata is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='GroupingRelationshipType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='GroupingRelationshipType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='GroupingRelationshipType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='GroupingRelationshipType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Type is not None:
            self.Type.export(write, level, 'maecPackage:', name_='Type', pretty_print=pretty_print)
        if self.Malware_Family_Name is not None:
            showIndent(write, level, pretty_print)
            write('<%sMalware_Family_Name>%s</%sMalware_Family_Name>%s' % ('maecPackage:', quote_xml(self.Malware_Family_Name), 'maecPackage:', eol_))
        if self.Malware_Toolkit_Name is not None:
            showIndent(write, level, pretty_print)
            write('<%sMalware_Toolkit_Name>%s</%sMalware_Toolkit_Name>%s' % ('maecPackage:', quote_xml(self.Malware_Toolkit_Name), 'maecPackage:', eol_))
        if self.Clustering_Metadata is not None:
            self.Clustering_Metadata.export(write, level, 'maecPackage:', name_='Clustering_Metadata', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Type':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Type(obj_)
        elif nodeName_ == 'Malware_Family_Name':
            Malware_Family_Name_ = child_.text
            Malware_Family_Name_ = self.gds_validate_string(Malware_Family_Name_, node, 'Malware_Family_Name')
            self.Malware_Family_Name = Malware_Family_Name_
        elif nodeName_ == 'Malware_Toolkit_Name':
            Malware_Toolkit_Name_ = child_.text
            Malware_Toolkit_Name_ = self.gds_validate_string(Malware_Toolkit_Name_, node, 'Malware_Toolkit_Name')
            self.Malware_Toolkit_Name = Malware_Toolkit_Name_
        elif nodeName_ == 'Clustering_Metadata':
            obj_ = ClusteringMetadataType.factory()
            obj_.build(child_)
            self.set_Clustering_Metadata(obj_)
# end class GroupingRelationshipType

class GroupingRelationshipListType(GeneratedsSuper):
    """The GroupingRelationshipListType captures a list of grouping
    relationships relating the Malware Subjects in a Package."""
    subclass = None
    superclass = None
    def __init__(self, Grouping_Relationship=None):
        if Grouping_Relationship is None:
            self.Grouping_Relationship = []
        else:
            self.Grouping_Relationship = Grouping_Relationship
    def factory(*args_, **kwargs_):
        if GroupingRelationshipListType.subclass:
            return GroupingRelationshipListType.subclass(*args_, **kwargs_)
        else:
            return GroupingRelationshipListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Grouping_Relationship(self): return self.Grouping_Relationship
    def set_Grouping_Relationship(self, Grouping_Relationship): self.Grouping_Relationship = Grouping_Relationship
    def add_Grouping_Relationship(self, value): self.Grouping_Relationship.append(value)
    def insert_Grouping_Relationship(self, index, value): self.Grouping_Relationship[index] = value
    def hasContent_(self):
        if (
            self.Grouping_Relationship
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='GroupingRelationshipListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='GroupingRelationshipListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='GroupingRelationshipListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='GroupingRelationshipListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Grouping_Relationship_ in self.Grouping_Relationship:
            Grouping_Relationship_.export(write, level, 'maecPackage:', name_='Grouping_Relationship', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Grouping_Relationship':
            obj_ = GroupingRelationshipType.factory()
            obj_.build(child_)
            self.Grouping_Relationship.append(obj_)
# end class GroupingRelationshipListType

class ClusteringMetadataType(GeneratedsSuper):
    """The ClusteringMetadataType specifies the metadata regarding a
    particular method used to cluster malware."""
    subclass = None
    superclass = None
    def __init__(self, Algorithm_Name=None, Algorithm_Version=None, Algorithm_Parameters=None, Cluster_Size=None, Cluster_Description=None, Cluster_Composition=None):
        self.Algorithm_Name = Algorithm_Name
        self.Algorithm_Version = Algorithm_Version
        self.Algorithm_Parameters = Algorithm_Parameters
        self.Cluster_Size = Cluster_Size
        self.Cluster_Description = Cluster_Description
        self.Cluster_Composition = Cluster_Composition
    def factory(*args_, **kwargs_):
        if ClusteringMetadataType.subclass:
            return ClusteringMetadataType.subclass(*args_, **kwargs_)
        else:
            return ClusteringMetadataType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Algorithm_Name(self): return self.Algorithm_Name
    def set_Algorithm_Name(self, Algorithm_Name): self.Algorithm_Name = Algorithm_Name
    def get_Algorithm_Version(self): return self.Algorithm_Version
    def set_Algorithm_Version(self, Algorithm_Version): self.Algorithm_Version = Algorithm_Version
    def get_Algorithm_Parameters(self): return self.Algorithm_Parameters
    def set_Algorithm_Parameters(self, Algorithm_Parameters): self.Algorithm_Parameters = Algorithm_Parameters
    def get_Cluster_Size(self): return self.Cluster_Size
    def set_Cluster_Size(self, Cluster_Size): self.Cluster_Size = Cluster_Size
    def get_Cluster_Description(self): return self.Cluster_Description
    def set_Cluster_Description(self, Cluster_Description): self.Cluster_Description = Cluster_Description
    def get_Cluster_Composition(self): return self.Cluster_Composition
    def set_Cluster_Composition(self, Cluster_Composition): self.Cluster_Composition = Cluster_Composition
    def hasContent_(self):
        if (
            self.Algorithm_Name is not None or
            self.Algorithm_Version is not None or
            self.Algorithm_Parameters is not None or
            self.Cluster_Size is not None or
            self.Cluster_Description is not None or
            self.Cluster_Composition is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ClusteringMetadataType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ClusteringMetadataType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ClusteringMetadataType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ClusteringMetadataType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Algorithm_Name is not None:
            showIndent(write, level, pretty_print)
            write('<%sAlgorithm_Name>%s</%sAlgorithm_Name>%s' % ('maecPackage:', quote_xml(self.Algorithm_Name), 'maecPackage:', eol_))
        if self.Algorithm_Version is not None:
            showIndent(write, level, pretty_print)
            write('<%sAlgorithm_Version>%s</%sAlgorithm_Version>%s' % ('maecPackage:', quote_xml(self.Algorithm_Version), 'maecPackage:', eol_))
        if self.Algorithm_Parameters is not None:
            self.Algorithm_Parameters.export(write, level, 'maecPackage:', name_='Algorithm_Parameters', pretty_print=pretty_print)
        if self.Cluster_Size is not None:
            showIndent(write, level, pretty_print)
            write('<%sCluster_Size>%s</%sCluster_Size>%s' % ('maecPackage:', self.gds_format_integer(self.Cluster_Size, input_name='Cluster_Size'), 'maecPackage:', eol_))
        if self.Cluster_Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sCluster_Description>%s</%sCluster_Description>%s' % ('maecPackage:', quote_xml(self.Cluster_Description), 'maecPackage:', eol_))
        if self.Cluster_Composition is not None:
            self.Cluster_Composition.export(write, level, 'maecPackage:', name_='Cluster_Composition', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Algorithm_Name':
            Algorithm_Name_ = child_.text
            Algorithm_Name_ = self.gds_validate_string(Algorithm_Name_, node, 'Algorithm_Name')
            self.Algorithm_Name = Algorithm_Name_
        elif nodeName_ == 'Algorithm_Version':
            Algorithm_Version_ = child_.text
            Algorithm_Version_ = self.gds_validate_string(Algorithm_Version_, node, 'Algorithm_Version')
            self.Algorithm_Version = Algorithm_Version_
        elif nodeName_ == 'Algorithm_Parameters':
            obj_ = ClusteringAlgorithmParametersType.factory()
            obj_.build(child_)
            self.set_Algorithm_Parameters(obj_)
        elif nodeName_ == 'Cluster_Size':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            if ival_ <= 0:
                raise_parse_error(child_, 'requires positiveInteger')
            ival_ = self.gds_validate_integer(ival_, node, 'Cluster_Size')
            self.Cluster_Size = ival_
        elif nodeName_ == 'Cluster_Description':
            Cluster_Description_ = child_.text
            Cluster_Description_ = self.gds_validate_string(Cluster_Description_, node, 'Cluster_Description')
            self.Cluster_Description = Cluster_Description_
        elif nodeName_ == 'Cluster_Composition':
            obj_ = ClusterCompositionType.factory()
            obj_.build(child_)
            self.set_Cluster_Composition(obj_)
# end class ClusteringMetadataType

class ClusterEdgeNodePairType(GeneratedsSuper):
    """The ClusterEdgeNodePairType captures a single edge-node pair in a
    malware cluster, which is composed of the two Malware Subjects
    that correspond to the nodes connected to the edge (via
    references), and represents the similarity index between the two
    Malware Subjects.The similarity_index field specifies the
    similarity index between the two Malware Subjects being
    referenced (indicating how similar they are), as a decimal
    value. This value should be equivalent to 1 minus the similarity
    distance value (if included).The similarity_index field
    specifies the similarity distance between the two Malware
    Subjects being referenced (indicating how dissimilar they are),
    as a decimal value. This value should be equivalent to 1 minus
    the similarity index value (if included)."""
    subclass = None
    superclass = None
    def __init__(self, similarity_distance=None, similarity_index=None, Malware_Subject_Node_A=None, Malware_Subject_Node_B=None):
        self.similarity_distance = _cast(float, similarity_distance)
        self.similarity_index = _cast(float, similarity_index)
        self.Malware_Subject_Node_A = Malware_Subject_Node_A
        self.Malware_Subject_Node_B = Malware_Subject_Node_B
    def factory(*args_, **kwargs_):
        if ClusterEdgeNodePairType.subclass:
            return ClusterEdgeNodePairType.subclass(*args_, **kwargs_)
        else:
            return ClusterEdgeNodePairType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Malware_Subject_Node_A(self): return self.Malware_Subject_Node_A
    def set_Malware_Subject_Node_A(self, Malware_Subject_Node_A): self.Malware_Subject_Node_A = Malware_Subject_Node_A
    def get_Malware_Subject_Node_B(self): return self.Malware_Subject_Node_B
    def set_Malware_Subject_Node_B(self, Malware_Subject_Node_B): self.Malware_Subject_Node_B = Malware_Subject_Node_B
    def get_similarity_distance(self): return self.similarity_distance
    def set_similarity_distance(self, similarity_distance): self.similarity_distance = similarity_distance
    def get_similarity_index(self): return self.similarity_index
    def set_similarity_index(self, similarity_index): self.similarity_index = similarity_index
    def hasContent_(self):
        if (
            self.Malware_Subject_Node_A is not None or
            self.Malware_Subject_Node_B is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ClusterEdgeNodePairType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ClusterEdgeNodePairType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ClusterEdgeNodePairType'):
        if self.similarity_distance is not None and 'similarity_distance' not in already_processed:
            already_processed.add('similarity_distance')
            write(' similarity_distance="%s"' % self.gds_format_float(self.similarity_distance, input_name='similarity_distance'))
        if self.similarity_index is not None and 'similarity_index' not in already_processed:
            already_processed.add('similarity_index')
            write(' similarity_index="%s"' % self.gds_format_float(self.similarity_index, input_name='similarity_index'))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ClusterEdgeNodePairType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Malware_Subject_Node_A is not None:
            self.Malware_Subject_Node_A.export(write, level, 'maecPackage:', name_='Malware_Subject_Node_A', pretty_print=pretty_print)
        if self.Malware_Subject_Node_B is not None:
            self.Malware_Subject_Node_B.export(write, level, 'maecPackage:', name_='Malware_Subject_Node_B', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('similarity_distance', node)
        if value is not None and 'similarity_distance' not in already_processed:
            already_processed.add('similarity_distance')
            try:
                self.similarity_distance = float(value)
            except ValueError, exp:
                raise ValueError('Bad float/double attribute (similarity_distance): %s' % exp)
        value = find_attr_value_('similarity_index', node)
        if value is not None and 'similarity_index' not in already_processed:
            already_processed.add('similarity_index')
            try:
                self.similarity_index = float(value)
            except ValueError, exp:
                raise ValueError('Bad float/double attribute (similarity_index): %s' % exp)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Malware_Subject_Node_A':
            obj_ = MalwareSubjectReferenceType.factory()
            obj_.build(child_)
            self.set_Malware_Subject_Node_A(obj_)
        elif nodeName_ == 'Malware_Subject_Node_B':
            obj_ = MalwareSubjectReferenceType.factory()
            obj_.build(child_)
            self.set_Malware_Subject_Node_B(obj_)
# end class ClusterEdgeNodePairType

class ClusterCompositionType(GeneratedsSuper):
    """The ClusterCompositionType captures the composition of a malware
    cluster via its edges and their respective connected nodes, as
    in an undirected graph.For clustering algorithms that may
    capture different types of scores, the score_type attribute
    specifies the type of score used to define the composition of
    this malware cluster."""
    subclass = None
    superclass = None
    def __init__(self, score_type=None, Edge_Node_Pair=None):
        self.score_type = _cast(None, score_type)
        if Edge_Node_Pair is None:
            self.Edge_Node_Pair = []
        else:
            self.Edge_Node_Pair = Edge_Node_Pair
    def factory(*args_, **kwargs_):
        if ClusterCompositionType.subclass:
            return ClusterCompositionType.subclass(*args_, **kwargs_)
        else:
            return ClusterCompositionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Edge_Node_Pair(self): return self.Edge_Node_Pair
    def set_Edge_Node_Pair(self, Edge_Node_Pair): self.Edge_Node_Pair = Edge_Node_Pair
    def add_Edge_Node_Pair(self, value): self.Edge_Node_Pair.append(value)
    def insert_Edge_Node_Pair(self, index, value): self.Edge_Node_Pair[index] = value
    def get_score_type(self): return self.score_type
    def set_score_type(self, score_type): self.score_type = score_type
    def hasContent_(self):
        if (
            self.Edge_Node_Pair
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ClusterCompositionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ClusterCompositionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ClusterCompositionType'):
        if self.score_type is not None and 'score_type' not in already_processed:
            already_processed.add('score_type')
            write(' score_type=%s' % (quote_attrib(self.score_type)))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ClusterCompositionType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Edge_Node_Pair_ in self.Edge_Node_Pair:
            Edge_Node_Pair_.export(write, level, 'maecPackage:', name_='Edge_Node_Pair', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('score_type', node)
        if value is not None and 'score_type' not in already_processed:
            already_processed.add('score_type')
            self.score_type = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Edge_Node_Pair':
            obj_ = ClusterEdgeNodePairType.factory()
            obj_.build(child_)
            self.Edge_Node_Pair.append(obj_)
# end class ClusterCompositionType

class ClusteringAlgorithmParametersType(GeneratedsSuper):
    """The ClusteringAlgorithmParametersType captures any parameters that
    may have been used in a malware clustering algorithm."""
    subclass = None
    superclass = None
    def __init__(self, Distance_Threshold=None, Number_of_Iterations=None):
        self.Distance_Threshold = Distance_Threshold
        self.Number_of_Iterations = Number_of_Iterations
    def factory(*args_, **kwargs_):
        if ClusteringAlgorithmParametersType.subclass:
            return ClusteringAlgorithmParametersType.subclass(*args_, **kwargs_)
        else:
            return ClusteringAlgorithmParametersType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Distance_Threshold(self): return self.Distance_Threshold
    def set_Distance_Threshold(self, Distance_Threshold): self.Distance_Threshold = Distance_Threshold
    def get_Number_of_Iterations(self): return self.Number_of_Iterations
    def set_Number_of_Iterations(self, Number_of_Iterations): self.Number_of_Iterations = Number_of_Iterations
    def hasContent_(self):
        if (
            self.Distance_Threshold is not None or
            self.Number_of_Iterations is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ClusteringAlgorithmParametersType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ClusteringAlgorithmParametersType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ClusteringAlgorithmParametersType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ClusteringAlgorithmParametersType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Distance_Threshold is not None:
            showIndent(write, level, pretty_print)
            write('<%sDistance_Threshold>%s</%sDistance_Threshold>%s' % ('maecPackage:', self.gds_format_float(self.Distance_Threshold, input_name='Distance_Threshold'), 'maecPackage:', eol_))
        if self.Number_of_Iterations is not None:
            showIndent(write, level, pretty_print)
            write('<%sNumber_of_Iterations>%s</%sNumber_of_Iterations>%s' % ('maecPackage:', self.gds_format_integer(self.Number_of_Iterations, input_name='Number_of_Iterations'), 'maecPackage:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Distance_Threshold':
            sval_ = child_.text
            try:
                fval_ = float(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires float or double: %s' % exp)
            fval_ = self.gds_validate_float(fval_, node, 'Distance_Threshold')
            self.Distance_Threshold = fval_
        elif nodeName_ == 'Number_of_Iterations':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            if ival_ <= 0:
                raise_parse_error(child_, 'requires positiveInteger')
            ival_ = self.gds_validate_integer(ival_, node, 'Number_of_Iterations')
            self.Number_of_Iterations = ival_
# end class ClusteringAlgorithmParametersType

class NetworkInfrastructureType(GeneratedsSuper):
    """The NetworkInfrastructureType captures specific details about the
    network infrastructure used in the malware analysis environment."""
    subclass = None
    superclass = None
    def __init__(self, Captured_Protocols=None):
        self.Captured_Protocols = Captured_Protocols
    def factory(*args_, **kwargs_):
        if NetworkInfrastructureType.subclass:
            return NetworkInfrastructureType.subclass(*args_, **kwargs_)
        else:
            return NetworkInfrastructureType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Captured_Protocols(self): return self.Captured_Protocols
    def set_Captured_Protocols(self, Captured_Protocols): self.Captured_Protocols = Captured_Protocols
    def hasContent_(self):
        if (
            self.Captured_Protocols is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='NetworkInfrastructureType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='NetworkInfrastructureType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='NetworkInfrastructureType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='NetworkInfrastructureType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Captured_Protocols is not None:
            self.Captured_Protocols.export(write, level, 'maecPackage:', name_='Captured_Protocols', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Captured_Protocols':
            obj_ = CapturedProtocolListType.factory()
            obj_.build(child_)
            self.set_Captured_Protocols(obj_)
# end class NetworkInfrastructureType

class ActionEquivalenceType(GeneratedsSuper):
    """The ActionEquivalenceType relates any Actions that are equivalent to
    each other, e.g., those that were found for the same Malware
    Subject when using different analysis tools. It can be used as a
    way of referencing equivalent actions as a single unit, such as
    for specifying the Action composition of a Behavior.The required
    id field specifies the ID for the Action Equivalence, and must
    be of the format specified by the ActionEquivalenceIDPattern
    type."""
    subclass = None
    superclass = None
    def __init__(self, id=None, Action_Reference=None):
        self.id = _cast(None, id)
        if Action_Reference is None:
            self.Action_Reference = []
        else:
            self.Action_Reference = Action_Reference
    def factory(*args_, **kwargs_):
        if ActionEquivalenceType.subclass:
            return ActionEquivalenceType.subclass(*args_, **kwargs_)
        else:
            return ActionEquivalenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action_Reference(self): return self.Action_Reference
    def set_Action_Reference(self, Action_Reference): self.Action_Reference = Action_Reference
    def add_Action_Reference(self, value): self.Action_Reference.append(value)
    def insert_Action_Reference(self, index, value): self.Action_Reference[index] = value
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Action_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ActionEquivalenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ActionEquivalenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ActionEquivalenceType'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ActionEquivalenceType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Action_Reference_ in self.Action_Reference:
            Action_Reference_.export(write, level, 'maecPackage:', name_='Action_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action_Reference':
            obj_ = cybox_core.ActionReferenceType.factory()
            obj_.build(child_)
            self.Action_Reference.append(obj_)
# end class ActionEquivalenceType

class ActionEquivalenceListType(GeneratedsSuper):
    """The ActionEquivalenceListType captures a list of Action
    Equivalences."""
    subclass = None
    superclass = None
    def __init__(self, Action_Equivalence=None):
        if Action_Equivalence is None:
            self.Action_Equivalence = []
        else:
            self.Action_Equivalence = Action_Equivalence
    def factory(*args_, **kwargs_):
        if ActionEquivalenceListType.subclass:
            return ActionEquivalenceListType.subclass(*args_, **kwargs_)
        else:
            return ActionEquivalenceListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action_Equivalence(self): return self.Action_Equivalence
    def set_Action_Equivalence(self, Action_Equivalence): self.Action_Equivalence = Action_Equivalence
    def add_Action_Equivalence(self, value): self.Action_Equivalence.append(value)
    def insert_Action_Equivalence(self, index, value): self.Action_Equivalence[index] = value
    def hasContent_(self):
        if (
            self.Action_Equivalence
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ActionEquivalenceListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ActionEquivalenceListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ActionEquivalenceListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ActionEquivalenceListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Action_Equivalence_ in self.Action_Equivalence:
            Action_Equivalence_.export(write, level, 'maecPackage:', name_='Action_Equivalence', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action_Equivalence':
            obj_ = ActionEquivalenceType.factory()
            obj_.build(child_)
            self.Action_Equivalence.append(obj_)
# end class ActionEquivalenceListType

class CapturedProtocolListType(GeneratedsSuper):
    """The CapturedProtocolListType specifies a list of network protocols
    that a malware analysis environment may capture or interact
    with."""
    subclass = None
    superclass = None
    def __init__(self, Protocol=None):
        if Protocol is None:
            self.Protocol = []
        else:
            self.Protocol = Protocol
    def factory(*args_, **kwargs_):
        if CapturedProtocolListType.subclass:
            return CapturedProtocolListType.subclass(*args_, **kwargs_)
        else:
            return CapturedProtocolListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Protocol(self): return self.Protocol
    def set_Protocol(self, Protocol): self.Protocol = Protocol
    def add_Protocol(self, value): self.Protocol.append(value)
    def insert_Protocol(self, index, value): self.Protocol[index] = value
    def hasContent_(self):
        if (
            self.Protocol
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='CapturedProtocolListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapturedProtocolListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='CapturedProtocolListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='CapturedProtocolListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Protocol_ in self.Protocol:
            Protocol_.export(write, level, 'maecPackage:', name_='Protocol', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Protocol':
            obj_ = CapturedProtocolType.factory()
            obj_.build(child_)
            self.Protocol.append(obj_)
# end class CapturedProtocolListType

class CapturedProtocolType(GeneratedsSuper):
    """The CapturedProtocolType specifies the details of a network protocol
    that may be captured or otherwise manipulated in the malware
    analysis environment.The layer7_protocol field specifies the
    name of the Layer 7 network protocol (OSI model) captured or
    manipulated by the analysis environment.The layer4_protocol
    field specifies the name of the Layer 4 network protocol (OSI
    model) captured or manipulated by the analysis environment.The
    port_number field specifies the port number for this network
    protocol that is captured or manipulated by the analysis
    environment.The interaction_level field specifies the relative
    level of interaction that the analysis environment has with the
    specified network protocol."""
    subclass = None
    superclass = None
    def __init__(self, layer7_protocol=None, port_number=None, interaction_level=None, layer4_protocol=None):
        self.layer7_protocol = _cast(None, layer7_protocol)
        self.port_number = _cast(int, port_number)
        self.interaction_level = _cast(None, interaction_level)
        self.layer4_protocol = _cast(None, layer4_protocol)
        pass
    def factory(*args_, **kwargs_):
        if CapturedProtocolType.subclass:
            return CapturedProtocolType.subclass(*args_, **kwargs_)
        else:
            return CapturedProtocolType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_layer7_protocol(self): return self.layer7_protocol
    def set_layer7_protocol(self, layer7_protocol): self.layer7_protocol = layer7_protocol
    def get_port_number(self): return self.port_number
    def set_port_number(self, port_number): self.port_number = port_number
    def get_interaction_level(self): return self.interaction_level
    def set_interaction_level(self, interaction_level): self.interaction_level = interaction_level
    def get_layer4_protocol(self): return self.layer4_protocol
    def set_layer4_protocol(self, layer4_protocol): self.layer4_protocol = layer4_protocol
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='CapturedProtocolType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapturedProtocolType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='CapturedProtocolType'):
        if self.layer7_protocol is not None and 'layer7_protocol' not in already_processed:
            already_processed.add('layer7_protocol')
            write(' layer7_protocol=%s' % (quote_attrib(self.layer7_protocol), ))
        if self.port_number is not None and 'port_number' not in already_processed:
            already_processed.add('port_number')
            write(' port_number="%s"' % self.gds_format_integer(self.port_number, input_name='port_number'))
        if self.interaction_level is not None and 'interaction_level' not in already_processed:
            already_processed.add('interaction_level')
            write(' interaction_level=%s' % (quote_attrib(self.interaction_level), ))
        if self.layer4_protocol is not None and 'layer4_protocol' not in already_processed:
            already_processed.add('layer4_protocol')
            write(' layer4_protocol=%s' % (quote_attrib(self.layer4_protocol), ))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='CapturedProtocolType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('layer7_protocol', node)
        if value is not None and 'layer7_protocol' not in already_processed:
            already_processed.add('layer7_protocol')
            self.layer7_protocol = value
        value = find_attr_value_('port_number', node)
        if value is not None and 'port_number' not in already_processed:
            already_processed.add('port_number')
            try:
                self.port_number = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
            if self.port_number <= 0:
                raise_parse_error(node, 'Invalid PositiveInteger')
        value = find_attr_value_('interaction_level', node)
        if value is not None and 'interaction_level' not in already_processed:
            already_processed.add('interaction_level')
            self.interaction_level = value
        value = find_attr_value_('layer4_protocol', node)
        if value is not None and 'layer4_protocol' not in already_processed:
            already_processed.add('layer4_protocol')
            self.layer4_protocol = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class CapturedProtocolType

class ObjectEquivalenceListType(GeneratedsSuper):
    """The ObjectEquivalenceListType captures a list of Object
    Equivalences."""
    subclass = None
    superclass = None
    def __init__(self, Object_Equivalence=None):
        if Object_Equivalence is None:
            self.Object_Equivalence = []
        else:
            self.Object_Equivalence = Object_Equivalence
    def factory(*args_, **kwargs_):
        if ObjectEquivalenceListType.subclass:
            return ObjectEquivalenceListType.subclass(*args_, **kwargs_)
        else:
            return ObjectEquivalenceListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Object_Equivalence(self): return self.Object_Equivalence
    def set_Object_Equivalence(self, Object_Equivalence): self.Object_Equivalence = Object_Equivalence
    def add_Object_Equivalence(self, value): self.Object_Equivalence.append(value)
    def insert_Object_Equivalence(self, index, value): self.Object_Equivalence[index] = value
    def hasContent_(self):
        if (
            self.Object_Equivalence
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ObjectEquivalenceListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ObjectEquivalenceListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ObjectEquivalenceListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ObjectEquivalenceListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Object_Equivalence_ in self.Object_Equivalence:
            Object_Equivalence_.export(write, level, 'maecPackage:', name_='Object_Equivalence', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Object_Equivalence':
            obj_ = ObjectEquivalenceType.factory()
            obj_.build(child_)
            self.Object_Equivalence.append(obj_)
# end class ObjectEquivalenceListType

class ObjectEquivalenceType(maec_bundle_schema.ObjectReferenceListType):
    """The ObjectEquivalenceType relates the Objects that are equivalent to
    each other, e.g., those that were found for the same Malware
    Subject when using different analysis tools.The required id
    field specifies the ID for the Object Equivalence, and must be
    of the format specified by the ObjectEquivalenceIDPattern type."""
    subclass = None
    superclass = maec_bundle_schema.ObjectReferenceListType
    def __init__(self, Object_Reference=None, id=None):
        super(ObjectEquivalenceType, self).__init__(Object_Reference, )
        self.id = _cast(None, id)
        pass
    def factory(*args_, **kwargs_):
        if ObjectEquivalenceType.subclass:
            return ObjectEquivalenceType.subclass(*args_, **kwargs_)
        else:
            return ObjectEquivalenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            super(ObjectEquivalenceType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='ObjectEquivalenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ObjectEquivalenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='ObjectEquivalenceType'):
        super(ObjectEquivalenceType, self).exportAttributes(write, level, already_processed, namespace_, name_='ObjectEquivalenceType')
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='ObjectEquivalenceType', fromsubclass_=False, pretty_print=True):
        super(ObjectEquivalenceType, self).exportChildren(write, level, 'maecPackage:', name_, True, pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
        super(ObjectEquivalenceType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        super(ObjectEquivalenceType, self).buildChildren(child_, node, nodeName_, True)
        pass
# end class ObjectEquivalenceType

class HypervisorHostSystemType(system_object.SystemObjectType):
    """The HypervisorHostSystemType characterizes the VM Hypervisor host
    system used in the malware analysis environment."""
    subclass = None
    superclass = system_object.SystemObjectType
    def __init__(self, object_reference=None, Custom_Properties=None, Available_Physical_Memory=None, BIOS_Info=None, Date=None, Hostname=None, Local_Time=None, Network_Interface_List=None, OS=None, Processor=None, Processor_Architecture=None, System_Time=None, Timezone_DST=None, Timezone_Standard=None, Total_Physical_Memory=None, Uptime=None, Username=None, VM_Hypervisor=None):
        super(HypervisorHostSystemType, self).__init__(object_reference, Custom_Properties, Available_Physical_Memory, BIOS_Info, Date, Hostname, Local_Time, Network_Interface_List, OS, Processor, Processor_Architecture, System_Time, Timezone_DST, Timezone_Standard, Total_Physical_Memory, Uptime, Username, )
        self.VM_Hypervisor = VM_Hypervisor
    def factory(*args_, **kwargs_):
        if HypervisorHostSystemType.subclass:
            return HypervisorHostSystemType.subclass(*args_, **kwargs_)
        else:
            return HypervisorHostSystemType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_VM_Hypervisor(self): return self.VM_Hypervisor
    def set_VM_Hypervisor(self, VM_Hypervisor): self.VM_Hypervisor = VM_Hypervisor
    def hasContent_(self):
        if (
            self.VM_Hypervisor is not None or
            super(HypervisorHostSystemType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='HypervisorHostSystemType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='HypervisorHostSystemType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='HypervisorHostSystemType'):
        super(HypervisorHostSystemType, self).exportAttributes(write, level, already_processed, namespace_, name_='HypervisorHostSystemType')
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='HypervisorHostSystemType', fromsubclass_=False, pretty_print=True):
        super(HypervisorHostSystemType, self).exportChildren(write, level, 'maecPackage:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.VM_Hypervisor is not None:
            self.VM_Hypervisor.export(write, level, 'maecPackage:', name_='VM_Hypervisor', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        super(HypervisorHostSystemType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'VM_Hypervisor':
            obj_ = cybox_common.PlatformSpecificationType.factory()
            obj_.build(child_)
            self.set_VM_Hypervisor(obj_)
        super(HypervisorHostSystemType, self).buildChildren(child_, node, nodeName_, True)
# end class HypervisorHostSystemType

class AnalysisSystemType(system_object.SystemObjectType):
    """The AnalysisSystemType is intended to characterize any systems on
    which malware analysis is performed. It imports and extends
    version 1.3 of the CybOX System Object."""
    subclass = None
    superclass = system_object.SystemObjectType
    def __init__(self, object_reference=None, Custom_Properties=None, Available_Physical_Memory=None, BIOS_Info=None, Date=None, Hostname=None, Local_Time=None, Network_Interface_List=None, OS=None, Processor=None, Processor_Architecture=None, System_Time=None, Timezone_DST=None, Timezone_Standard=None, Total_Physical_Memory=None, Uptime=None, Username=None, Installed_Programs=None):
        super(AnalysisSystemType, self).__init__(object_reference, Custom_Properties, Available_Physical_Memory, BIOS_Info, Date, Hostname, Local_Time, Network_Interface_List, OS, Processor, Processor_Architecture, System_Time, Timezone_DST, Timezone_Standard, Total_Physical_Memory, Uptime, Username, )
        self.Installed_Programs = Installed_Programs
    def factory(*args_, **kwargs_):
        if AnalysisSystemType.subclass:
            return AnalysisSystemType.subclass(*args_, **kwargs_)
        else:
            return AnalysisSystemType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Installed_Programs(self): return self.Installed_Programs
    def set_Installed_Programs(self, Installed_Programs): self.Installed_Programs = Installed_Programs
    def hasContent_(self):
        if (
            self.Installed_Programs is not None or
            super(AnalysisSystemType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='AnalysisSystemType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AnalysisSystemType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='AnalysisSystemType'):
        super(AnalysisSystemType, self).exportAttributes(write, level, already_processed, namespace_, name_='AnalysisSystemType')
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='AnalysisSystemType', fromsubclass_=False, pretty_print=True):
        super(AnalysisSystemType, self).exportChildren(write, level, 'maecPackage:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Installed_Programs is not None:
            self.Installed_Programs.export(write, level, 'maecPackage:', name_='Installed_Programs', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        super(AnalysisSystemType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Installed_Programs':
            obj_ = InstalledProgramsType.factory()
            obj_.build(child_)
            self.set_Installed_Programs(obj_)
        super(AnalysisSystemType, self).buildChildren(child_, node, nodeName_, True)
# end class AnalysisSystemType

class CommentType(cybox_common.StructuredTextType):
    """The CommentType captures a comment relating to some MAEC entity.The
    author field specifies the name of the author that added the
    comment.The timestamp field specifies the date/time that the
    comment was added."""
    subclass = None
    superclass = cybox_common.StructuredTextType
    def __init__(self, structuring_format=None, timestamp=None, author=None, observation_name=None, valueOf_=None):
        super(CommentType, self).__init__(structuring_format, valueOf_, )
        self.timestamp = _cast(None, timestamp)
        self.author = _cast(None, author)
        self.observation_name = observation_name
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if CommentType.subclass:
            return CommentType.subclass(*args_, **kwargs_)
        else:
            return CommentType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_timestamp(self): return self.timestamp
    def set_timestamp(self, timestamp): self.timestamp = timestamp
    def get_author(self): return self.author
    def set_author(self, author): self.author = author
    def get_observation_name(self): return self.observation_name
    def set_observation_name(self, observation_name): self.observation_name = observation_name
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def hasContent_(self):
        if (
            self.valueOf_ or
            super(CommentType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='CommentType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CommentType')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='CommentType'):
        super(CommentType, self).exportAttributes(write, level, already_processed, namespace_, name_='CommentType')
        if self.timestamp is not None and 'timestamp' not in already_processed:
            already_processed.add('timestamp')
            write(' timestamp="%s"' % self.gds_format_datetime(self.timestamp, input_name='timestamp'))
        if self.author is not None and 'author' not in already_processed:
            already_processed.add('author')
            write(' author=%s' % (quote_attrib(self.author)))
        if self.observation_name is not None and 'observation_name' not in already_processed:
            already_processed.add('observation_name')
            write(' observation_name=%s' % (quote_attrib(self.observation_name)))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='CommentType', fromsubclass_=False, pretty_print=True):
        super(CommentType, self).exportChildren(write, level, 'maecPackage:', name_, True, pretty_print=pretty_print)
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('timestamp', node)
        if value is not None and 'timestamp' not in already_processed:
            already_processed.add('timestamp')
            try:
                self.timestamp = value
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (timestamp): %s' % exp)
        value = find_attr_value_('author', node)
        if value is not None and 'author' not in already_processed:
            already_processed.add('author')
            self.author = value
        super(CommentType, self).buildAttributes(node, attrs, already_processed)
        value = find_attr_value_('observation_name', node)
        if value is not None and 'observation_name' not in already_processed:
            already_processed.add('observation_name')
            self.observation_name = value
        super(CommentType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class CommentType

class MalwareExceptionType(cybox_common.ErrorType):
    """The MalwareExceptionType captures details of exceptions that may be
    raised as a result of a malware instance executing on a
    system.The is_fatal field specifies whether the exception is
    fatal; that is, whether it caused the malware instance to
    terminate."""
    subclass = None
    superclass = cybox_common.ErrorType
    def __init__(self, is_fatal=None, Error_Type=None, Error_Count=None, Error_Instances=None, Exception_Code=None, Faulting_Address=None, Description=None):
        super(MalwareExceptionType, self).__init__(Error_Type=None, Error_Count=None, Error_Instances=None)
        self.is_fatal = _cast(bool, is_fatal)
        self.Exception_Code = Exception_Code
        self.Faulting_Address = Faulting_Address
        self.Description = Description
    def factory(*args_, **kwargs_):
        if MalwareExceptionType.subclass:
            return MalwareExceptionType.subclass(*args_, **kwargs_)
        else:
            return MalwareExceptionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Exception_Code(self): return self.Exception_Code
    def set_Exception_Code(self, Exception_Code): self.Exception_Code = Exception_Code
    def get_Faulting_Address(self): return self.Faulting_Address
    def set_Faulting_Address(self, Faulting_Address): self.Faulting_Address = Faulting_Address
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_is_fatal(self): return self.is_fatal
    def set_is_fatal(self, is_fatal): self.is_fatal = is_fatal
    def hasContent_(self):
        if (
            self.Exception_Code is not None or
            self.Faulting_Address is not None or
            self.Description is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareExceptionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareExceptionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareExceptionType'):
        super(MalwareExceptionType, self).exportAttributes(write, level, already_processed, namespace_, name_='MalwareExceptionType')
        if self.is_fatal is not None and 'is_fatal' not in already_processed:
            already_processed.add('is_fatal')
            write(' is_fatal="%s"' % self.gds_format_boolean(self.is_fatal, input_name='is_fatal'))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareExceptionType', fromsubclass_=False, pretty_print=True):
        super(MalwareExceptionType, self).exportChildren(write, level, namespace_, name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Exception_Code is not None:
            showIndent(write, level, pretty_print)
            write('<%sException_Code>%s</%sException_Code>%s' % (namespace_, quote_xml(self.Exception_Code), namespace_, eol_))
        if self.Faulting_Address is not None:
            showIndent(write, level, pretty_print)
            write('<%sFaulting_Address>%s</%sFaulting_Address>%s' % (namespace_, quote_xml(self.Faulting_Address), namespace_, eol_))
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % (namespace_, self.gds_format_integer(self.Description, input_name='Description'), namespace_, eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('is_fatal', node)
        if value is not None and 'is_fatal' not in already_processed:
            already_processed.add('is_fatal')
            if value in ('true', '1'):
                self.is_fatal = True
            elif value in ('false', '0'):
                self.is_fatal = False
            else:
                raise_parse_error(node, 'Bad boolean attribute')
        super(MalwareExceptionType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Exception_Code':
            Exception_Code_ = child_.text
            Exception_Code_ = self.gds_validate_string(Exception_Code_, node, 'Exception_Code')
            self.Exception_Code = Exception_Code_
        elif nodeName_ == 'Faulting_Address':
            Faulting_Address_ = child_.text
            Faulting_Address_ = self.gds_validate_string(Faulting_Address_, node, 'Faulting_Address')
            self.Faulting_Address = Faulting_Address_
        elif nodeName_ == 'Description':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'Description')
            self.Description = ival_
        super(MalwareExceptionType, self).buildChildren(child_, node, nodeName_, True)
# end class MalwareExceptionType

class MalwareDevelopmentEnvironmentType(GeneratedsSuper):
    """The MalwareDevelopmentEnvironmentType captures details of the
    development environment used in developing the malware instance,
    such as information on any tools that were used."""
    subclass = None
    superclass = None
    def __init__(self, Tools=None, Debugging_File=None):
        self.Tools = Tools
        if Debugging_File is None:
            self.Debugging_File = []
        else:
            self.Debugging_File = Debugging_File
    def factory(*args_, **kwargs_):
        if MalwareDevelopmentEnvironmentType.subclass:
            return MalwareDevelopmentEnvironmentType.subclass(*args_, **kwargs_)
        else:
            return MalwareDevelopmentEnvironmentType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Tools(self): return self.Tools
    def set_Tools(self, Tools): self.Tools = Tools
    def get_Debugging_File(self): return self.Debugging_File
    def set_Debugging_File(self, Debugging_File): self.Debugging_File = Debugging_File
    def add_Debugging_File(self, value): self.Debugging_File.append(value)
    def insert_Debugging_File(self, index, value): self.Debugging_File[index] = value
    def hasContent_(self):
        if (
            self.Tools is not None or
            self.Debugging_File
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareDevelopmentEnvironmentType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareDevelopmentEnvironmentType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareDevelopmentEnvironmentType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareDevelopmentEnvironmentType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Tools is not None:
            self.Tools.export(write, level, namespace_, name_='Tools', pretty_print=pretty_print)
        for Debugging_File_ in self.Debugging_File:
            Debugging_File_.export(write, level, namespace_, name_='Debugging_File', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Tools':
            obj_ = cybox_common.ToolsInformationType.factory()
            obj_.build(child_)
            self.set_Tools(obj_)
        elif nodeName_ == 'Debugging_File':
            obj_ = file_object.FileObjectType.factory()
            obj_.build(child_)
            self.Debugging_File.append(obj_)
# end class MalwareDevelopmentEnvironmentType

class MalwareConfigurationParameterType(GeneratedsSuper):
    """The MalwareConfigurationParameterType captures a single
    configuration parameter that may be defined for a malware
    instance, as a name/value pair."""
    subclass = None
    superclass = None
    def __init__(self, Name=None, Value=None):
        self.Name = Name
        self.Value = Value
    def factory(*args_, **kwargs_):
        if MalwareConfigurationParameterType.subclass:
            return MalwareConfigurationParameterType.subclass(*args_, **kwargs_)
        else:
            return MalwareConfigurationParameterType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Name(self): return self.Name
    def set_Name(self, Name): self.Name = Name
    def get_Value(self): return self.Value
    def set_Value(self, Value): self.Value = Value
    def hasContent_(self):
        if (
            self.Name is not None or
            self.Value is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationParameterType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareConfigurationParameterType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareConfigurationParameterType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationParameterType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Name is not None:
            self.Name.export(write, level, 'maecPackage:', name_='Name', pretty_print=pretty_print)
        if self.Value is not None:
            showIndent(write, level, pretty_print)
            write('<%sValue>%s</%sValue>%s' % ('maecPackage:', quote_xml(self.Value), 'maecPackage:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Name':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Name(obj_)
        elif nodeName_ == 'Value':
            Value_ = child_.text
            Value_ = self.gds_validate_string(Value_, node, 'Value')
            self.Value = Value_
# end class MalwareConfigurationParameterType

class MalwareConfigurationDetailsType(GeneratedsSuper):
    """The MalwareConfigurationDetailsType captures details of malware
    configuration parameters and associated metadata."""
    subclass = None
    superclass = None
    def __init__(self, Storage=None, Obfuscation=None, Configuration_Parameter=None):
        self.Storage = Storage
        self.Obfuscation = Obfuscation
        if Configuration_Parameter is None:
            self.Configuration_Parameter = []
        else:
            self.Configuration_Parameter = Configuration_Parameter
    def factory(*args_, **kwargs_):
        if MalwareConfigurationDetailsType.subclass:
            return MalwareConfigurationDetailsType.subclass(*args_, **kwargs_)
        else:
            return MalwareConfigurationDetailsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Storage(self): return self.Storage
    def set_Storage(self, Storage): self.Storage = Storage
    def get_Obfuscation(self): return self.Obfuscation
    def set_Obfuscation(self, Obfuscation): self.Obfuscation = Obfuscation
    def get_Configuration_Parameter(self): return self.Configuration_Parameter
    def set_Configuration_Parameter(self, Configuration_Parameter): self.Configuration_Parameter = Configuration_Parameter
    def add_Configuration_Parameter(self, value): self.Configuration_Parameter.append(value)
    def insert_Configuration_Parameter(self, index, value): self.Configuration_Parameter[index] = value
    def hasContent_(self):
        if (
            self.Storage is not None or
            self.Obfuscation is not None or
            self.Configuration_Parameter
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationDetailsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareConfigurationDetailsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareConfigurationDetailsType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationDetailsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Storage is not None:
            self.Storage.export(write, level, 'maecPackage:', name_='Storage', pretty_print=pretty_print)
        if self.Obfuscation is not None:
            self.Obfuscation.export(write, level, 'maecPackage:', name_='Obfuscation', pretty_print=pretty_print)
        for Configuration_Parameter_ in self.Configuration_Parameter:
            Configuration_Parameter_.export(write, level, 'maecPackage:', name_='Configuration_Parameter', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Storage':
            obj_ = MalwareConfigurationStorageDetailsType.factory()
            obj_.build(child_)
            self.set_Storage(obj_)
        elif nodeName_ == 'Obfuscation':
            obj_ = MalwareConfigurationObfuscationDetailsType.factory()
            obj_.build(child_)
            self.set_Obfuscation(obj_)
        elif nodeName_ == 'Configuration_Parameter':
            obj_ = MalwareConfigurationParameterType.factory()
            obj_.build(child_)
            self.Configuration_Parameter.append(obj_)
# end class MalwareConfigurationDetailsType

class MalwareConfigurationObfuscationDetailsType(GeneratedsSuper):
    """The MalwareConfigurationObfuscationDetailsType captures details
    relating to the obfuscation of malware configuration
    parameters.The is_encoded field specifies that the malware
    configuration parameters are encoded with the algorithm captured
    in the Algorithm_Details field.The is_encrypted field specifies
    that the malware configuration parameters are encrypted with the
    algorithm captured in the Algorithm_Details field."""
    subclass = None
    superclass = None
    def __init__(self, is_encoded=None, is_encrypted=None, Algorithm_Details=None):
        self.is_encoded = _cast(bool, is_encoded)
        self.is_encrypted = _cast(bool, is_encrypted)
        if Algorithm_Details is None:
            self.Algorithm_Details = []
        else:
            self.Algorithm_Details = Algorithm_Details
    def factory(*args_, **kwargs_):
        if MalwareConfigurationObfuscationDetailsType.subclass:
            return MalwareConfigurationObfuscationDetailsType.subclass(*args_, **kwargs_)
        else:
            return MalwareConfigurationObfuscationDetailsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Algorithm_Details(self): return self.Algorithm_Details
    def set_Algorithm_Details(self, Algorithm_Details): self.Algorithm_Details = Algorithm_Details
    def add_Algorithm_Details(self, value): self.Algorithm_Details.append(value)
    def insert_Algorithm_Details(self, index, value): self.Algorithm_Details[index] = value
    def get_is_encoded(self): return self.is_encoded
    def set_is_encoded(self, is_encoded): self.is_encoded = is_encoded
    def get_is_encrypted(self): return self.is_encrypted
    def set_is_encrypted(self, is_encrypted): self.is_encrypted = is_encrypted
    def hasContent_(self):
        if (
            self.Algorithm_Details
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationObfuscationDetailsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareConfigurationObfuscationDetailsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareConfigurationObfuscationDetailsType'):
        if self.is_encoded is not None and 'is_encoded' not in already_processed:
            already_processed.add('is_encoded')
            write(' is_encoded="%s"' % self.gds_format_boolean(self.is_encoded, input_name='is_encoded'))
        if self.is_encrypted is not None and 'is_encrypted' not in already_processed:
            already_processed.add('is_encrypted')
            write(' is_encrypted="%s"' % self.gds_format_boolean(self.is_encrypted, input_name='is_encrypted'))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationObfuscationDetailsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Algorithm_Details_ in self.Algorithm_Details:
            Algorithm_Details_.export(write, level, 'maecPackage:', name_='Algorithm_Details', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('is_encoded', node)
        if value is not None and 'is_encoded' not in already_processed:
            already_processed.add('is_encoded')
            if value in ('true', '1'):
                self.is_encoded = True
            elif value in ('false', '0'):
                self.is_encoded = False
            else:
                raise_parse_error(node, 'Bad boolean attribute')
        value = find_attr_value_('is_encrypted', node)
        if value is not None and 'is_encrypted' not in already_processed:
            already_processed.add('is_encrypted')
            if value in ('true', '1'):
                self.is_encrypted = True
            elif value in ('false', '0'):
                self.is_encrypted = False
            else:
                raise_parse_error(node, 'Bad boolean attribute')
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Algorithm_Details':
            obj_ = MalwareConfigurationObfuscationAlgorithmType.factory()
            obj_.build(child_)
            self.Algorithm_Details.append(obj_)
# end class MalwareConfigurationObfuscationDetailsType

class MalwareConfigurationObfuscationAlgorithmType(GeneratedsSuper):
    """The MalwareConfigurationObfuscationDetailsType captures of an
    algorithm used to encode or encrypt malware configuration
    parameters.The ordinal_position field specifies the explicit
    ordering of the usage of the algorithm with respect to the other
    algorithms used to encrypt or encode the malware configuration
    parameters, for cases where more than one algorithm was used."""
    subclass = None
    superclass = None
    def __init__(self, ordinal_position=None, Key=None, Algorithm_Name=None):
        self.ordinal_position = _cast(int, ordinal_position)
        self.Key = Key
        self.Algorithm_Name = Algorithm_Name
    def factory(*args_, **kwargs_):
        if MalwareConfigurationObfuscationAlgorithmType.subclass:
            return MalwareConfigurationObfuscationAlgorithmType.subclass(*args_, **kwargs_)
        else:
            return MalwareConfigurationObfuscationAlgorithmType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Key(self): return self.Key
    def set_Key(self, Key): self.Key = Key
    def get_Algorithm_Name(self): return self.Algorithm_Name
    def set_Algorithm_Name(self, Algorithm_Name): self.Algorithm_Name = Algorithm_Name
    def get_ordinal_position(self): return self.ordinal_position
    def set_ordinal_position(self, ordinal_position): self.ordinal_position = ordinal_position
    def hasContent_(self):
        if (
            self.Key is not None or
            self.Algorithm_Name is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationObfuscationAlgorithmType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareConfigurationObfuscationAlgorithmType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareConfigurationObfuscationAlgorithmType'):
        if self.ordinal_position is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            write(' ordinal_position="%s"' % self.gds_format_integer(self.ordinal_position, input_name='ordinal_position'))
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationObfuscationAlgorithmType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Key is not None:
            showIndent(write, level, pretty_print)
            write('<%sKey>%s</%sKey>%s' % ('maecPackage:', quote_xml(self.Key), 'maecPackage:', eol_))
        if self.Algorithm_Name is not None:
            self.Algorithm_Name.export(write, level, 'maecPackage:', name_='Algorithm_Name', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('ordinal_position', node)
        if value is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            try:
                self.ordinal_position = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
            if self.ordinal_position <= 0:
                raise_parse_error(node, 'Invalid PositiveInteger')
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Key':
            Key_ = child_.text
            Key_ = self.gds_validate_string(Key_, node, 'Key')
            self.Key = Key_
        elif nodeName_ == 'Algorithm_Name':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Algorithm_Name(obj_)
# end class MalwareConfigurationObfuscationAlgorithmType

class MalwareConfigurationStorageDetailsType(GeneratedsSuper):
    """The MalwareConfigurationStorageDetailsType captures details relating
    to the storage of malware configuration parameters."""
    subclass = None
    superclass = None
    def __init__(self, Malware_Binary=None, File=None, URL=None):
        self.Malware_Binary = Malware_Binary
        self.File = File
        if URL is None:
            self.URL = []
        else:
            self.URL = URL
    def factory(*args_, **kwargs_):
        if MalwareConfigurationStorageDetailsType.subclass:
            return MalwareConfigurationStorageDetailsType.subclass(*args_, **kwargs_)
        else:
            return MalwareConfigurationStorageDetailsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Malware_Binary(self): return self.Malware_Binary
    def set_Malware_Binary(self, Malware_Binary): self.Malware_Binary = Malware_Binary
    def get_File(self): return self.File
    def set_File(self, File): self.File = File
    def get_URL(self): return self.URL
    def set_URL(self, URL): self.URL = URL
    def add_URL(self, value): self.URL.append(value)
    def insert_URL(self, index, value): self.URL[index] = value
    def hasContent_(self):
        if (
            self.Malware_Binary is not None or
            self.File is not None or
            self.URL
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationStorageDetailsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareConfigurationStorageDetailsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareConfigurationStorageDetailsType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareConfigurationStorageDetailsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Malware_Binary is not None:
            self.Malware_Binary.export(write, level, 'maecPackage:', name_='Malware_Binary', pretty_print=pretty_print)
        if self.File is not None:
            self.File.export(write, level, 'maecPackage:', name_='File', pretty_print=pretty_print)
        for URL_ in self.URL:
            URL_.export(write, level, 'maecPackage:', name_='URL', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Malware_Binary':
            obj_ = MalwareBinaryConfigurationStorageDetailsType.factory()
            obj_.build(child_)
            self.set_Malware_Binary(obj_)
        elif nodeName_ == 'File':
            obj_ = file_object.FileObjectType.factory()
            obj_.build(child_)
            self.set_File(obj_)
        elif nodeName_ == 'URL':
            obj_ = uri_object.URIObjectType.factory()
            obj_.build(child_)
            self.URL.append(obj_)
# end class MalwareConfigurationStorageDetailsType

class MalwareBinaryConfigurationStorageDetailsType(GeneratedsSuper):
    """The MalwareBinaryConfigurationStorageDetailsType captures details
    relating to the storage of malware configuration parameters
    inside the malware binary itself."""
    subclass = None
    superclass = None
    def __init__(self, File_Offset=None, Section_Name=None, Section_Offset=None):
        self.File_Offset = File_Offset
        self.Section_Name = Section_Name
        self.Section_Offset = Section_Offset
    def factory(*args_, **kwargs_):
        if MalwareBinaryConfigurationStorageDetailsType.subclass:
            return MalwareBinaryConfigurationStorageDetailsType.subclass(*args_, **kwargs_)
        else:
            return MalwareBinaryConfigurationStorageDetailsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_File_Offset(self): return self.File_Offset
    def set_File_Offset(self, File_Offset): self.File_Offset = File_Offset
    def get_Section_Name(self): return self.Section_Name
    def set_Section_Name(self, Section_Name): self.Section_Name = Section_Name
    def get_Section_Offset(self): return self.Section_Offset
    def set_Section_Offset(self, Section_Offset): self.Section_Offset = Section_Offset
    def hasContent_(self):
        if (
            self.File_Offset is not None or
            self.Section_Name is not None or
            self.Section_Offset is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecPackage:', name_='MalwareBinaryConfigurationStorageDetailsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareBinaryConfigurationStorageDetailsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecPackage:', name_='MalwareBinaryConfigurationStorageDetailsType'):
        pass
    def exportChildren(self, write, level, namespace_='maecPackage:', name_='MalwareBinaryConfigurationStorageDetailsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.File_Offset is not None:
            showIndent(write, level, pretty_print)
            write('<%sFile_Offset>%s</%sFile_Offset>%s' % ('maecPackage:', quote_xml(self.File_Offset), 'maecPackage:', eol_))
        if self.Section_Name is not None:
            showIndent(write, level, pretty_print)
            write('<%sSection_Name>%s</%sSection_Name>%s' % ('maecPackage:', quote_xml(self.Section_Name), 'maecPackage:', eol_))
        if self.Section_Offset is not None:
            showIndent(write, level, pretty_print)
            write('<%sSection_Offset>%s</%sSection_Offset>%s' % ('maecPackage:', quote_xml(self.Section_Offset), 'maecPackage:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'File_Offset':
            File_Offset_ = child_.text
            File_Offset_ = self.gds_validate_string(File_Offset_, node, 'File_Offset')
            self.File_Offset = File_Offset_
        elif nodeName_ == 'Section_Name':
            Section_Name_ = child_.text
            Section_Name_ = self.gds_validate_string(Section_Name_, node, 'Section_Name')
            self.Section_Name = Section_Name_
        elif nodeName_ == 'Section_Offset':
            Section_Offset_ = child_.text
            Section_Offset_ = self.gds_validate_string(Section_Offset_, node, 'Section_Offset')
            self.Section_Offset = Section_Offset_
# end class MalwareBinaryConfigurationStorageDetailsType

USAGE_TEXT = """
Usage: python <Parser>.py [ -s ] <in_xml_file>
"""

def usage():
    print USAGE_TEXT
    sys.exit(1)

def get_root_tag(node):
    tag = Tag_pattern_.match(node.tag).groups()[-1]
    rootClass = GDSClassesMapping.get(tag)
    if rootClass is None:
        rootClass = globals().get(tag)
    return tag, rootClass

def parse(inFileName):
    doc = parsexml_(inFileName)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    #sys.stdout.write('<?xml version="1.0" ?>\n')
    #rootObj.export(sys.stdout, 0, name_=rootTag,
    #    namespacedef_='',
    #    pretty_print=True)
    return rootObj

def parseEtree(inFileName):
    doc = parsexml_(inFileName)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    rootElement = rootObj.to_etree(None, name_=rootTag)
    content = etree_.tostring(rootElement, pretty_print=True,
        xml_declaration=True, encoding="utf-8")
    sys.stdout.write(content)
    sys.stdout.write('\n')
    return rootObj, rootElement

def parseString(inString):
    from StringIO import StringIO
    doc = parsexml_(StringIO(inString))
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    #sys.stdout.write('<?xml version="1.0" ?>\n')
    #rootObj.export(sys.stdout, 0, name_="MAEC_Package",
    #   namespacedef_='')
    return rootObj

def parseLiteral(inFileName):
    doc = parsexml_(inFileName)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('#from maec_package_temp import *\n\n')
    sys.stdout.write('from datetime import datetime as datetime_\n\n')
    sys.stdout.write('import maec_package_temp as model_\n\n')
    sys.stdout.write('rootObj = model_.rootTag(\n')
    rootObj.exportLiteral(sys.stdout, 0, name_=rootTag)
    sys.stdout.write(')\n')
    return rootObj

def main():
    args = sys.argv[1:]
    if len(args) == 1:
        parse(args[0])
    else:
        usage()

if __name__ == '__main__':
    #import pdb; pdb.set_trace()
    main()

__all__ = [
    "AnalysisEnvironmentType",
    "SourceType",
    "CommentListType",
    "AnalysisSystemListType",
    "ToolListType",
    "CommentType",
    "AnalysisSystemType",
    "HypervisorHostSystemType",
    "DynamicAnalysisMetadataType",
    "AnalysisType",
    "AnalysisListType",
    "InstalledProgramsType",
    "PackageType",
    "MalwareSubjectType",
    "MetaAnalysisType",
    "MalwareSubjectRelationshipType",
    "MalwareSubjectRelationshipListType",
    "MalwareSubjectReferenceType",
    "MalwareSubjectListType",
    "MinorVariantListType",
    "FindingsBundleListType",
    "GroupingRelationshipType",
    "GroupingRelationshipListType",
    "ClusteringMetadataType",
    "ClusterEdgeNodePairType",
    "ClusterCompositionType",
    "ClusteringAlgorithmParametersType",
    "NetworkInfrastructureType",
    "ActionEquivalenceType",
    "ActionEquivalenceListType",
    "CapturedProtocolListType",
    "CapturedProtocolType",
    "ObjectEquivalenceType",
    "ObjectEquivalenceListType"
    ]

GDSClassesMapping = {
    "AnalysisEnvironmentType": AnalysisEnvironmentType,
    "SourceType": SourceType,
    "CommentListType": CommentListType,
    "AnalysisSystemListType": AnalysisSystemListType,
    "ToolListType": ToolListType,
    "CommentType": CommentType,
    "AnalysisSystemType": AnalysisSystemType,
    "HypervisorHostSystemType": HypervisorHostSystemType,
    "DynamicAnalysisMetadataType": DynamicAnalysisMetadataType,
    "AnalysisType": AnalysisType,
    "AnalysisListType": AnalysisListType,
    "InstalledProgramsType": InstalledProgramsType,
    "MAEC_Package": PackageType,
    "MalwareSubjectType": MalwareSubjectType,
    "MetaAnalysisType": MetaAnalysisType,
    "MalwareSubjectRelationshipType": MalwareSubjectRelationshipType,
    "MalwareSubjectRelationshipListType": MalwareSubjectRelationshipListType,
    "MalwareSubjectReferenceType": MalwareSubjectReferenceType,
    "MalwareSubjectListType": MalwareSubjectListType,
    "MinorVariantListType": MinorVariantListType,
    "FindingsBundleListType": FindingsBundleListType,
    "GroupingRelationshipType": GroupingRelationshipType,
    "GroupingRelationshipListType": GroupingRelationshipListType,
    "ClusteringMetadataType": ClusteringMetadataType,
    "ClusterEdgeNodePairType": ClusterEdgeNodePairType,
    "ClusterCompositionType": ClusterCompositionType,
    "ClusteringAlgorithmParametersType": ClusteringAlgorithmParametersType,
    "NetworkInfrastructureType": NetworkInfrastructureType,
    "ActionEquivalenceType": ActionEquivalenceType,
    "ActionEquivalenceListType": ActionEquivalenceListType,
    "CapturedProtocolListType": CapturedProtocolListType,
    "CapturedProtocolType": CapturedProtocolType,
    "ObjectEquivalenceType": ObjectEquivalenceType,
    "ObjectEquivalenceListType": ObjectEquivalenceListType
}
