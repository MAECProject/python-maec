# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys

from mixbox.binding_utils import *

from cybox.bindings import cybox_core
from cybox.bindings import cybox_common
from cybox.bindings import code_object
from cybox.bindings import process_object

class BehaviorType(GeneratedsSuper):
    """The BehaviorType is one of the foundational MAEC types, and serves
    as a method for the characterization of malicious behaviors
    found or observed in malware. Behaviors can be thought of as
    representing the purpose behind groups of MAEC Actions, and are
    therefore representative of distinct portions of higher-level
    malware functionality. Thus, while a malware instance may
    perform some multitude of Actions, it is likely that these
    Actions represent only a few distinct behaviors. Some examples
    include vulnerability exploitation, email address harvesting,
    the disabling of a security service, etc.The required id field
    specifies a unique ID for this Behavior. The ID must follow the
    pattern defined in the BehaviorIDPattern simple type.The
    ordinal_position field specifies the ordinal position of the
    Behavior with respect to the execution of the malware.The status
    field specifies the execution status of the Behavior being
    characterized.The duration field specifies the duration of the
    Behavior. One way to derive such a value may be to calculate the
    difference between the timestamps of the first and last actions
    that compose the behavior."""
    subclass = None
    superclass = None
    def __init__(self, status=None, duration=None, ordinal_position=None, id=None, Purpose=None, Description=None, Discovery_Method=None, Action_Composition=None, Associated_Code=None, Relationships=None):
        self.status = _cast(None, status)
        self.duration = _cast(None, duration)
        self.ordinal_position = _cast(int, ordinal_position)
        self.id = _cast(None, id)
        self.Purpose = Purpose
        self.Description = Description
        self.Discovery_Method = Discovery_Method
        self.Action_Composition = Action_Composition
        self.Associated_Code = Associated_Code
        self.Relationships = Relationships
    def factory(*args_, **kwargs_):
        if BehaviorType.subclass:
            return BehaviorType.subclass(*args_, **kwargs_)
        else:
            return BehaviorType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Purpose(self): return self.Purpose
    def set_Purpose(self, Purpose): self.Purpose = Purpose
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_Discovery_Method(self): return self.Discovery_Method
    def set_Discovery_Method(self, Discovery_Method): self.Discovery_Method = Discovery_Method
    def get_Action_Composition(self): return self.Action_Composition
    def set_Action_Composition(self, Action_Composition): self.Action_Composition = Action_Composition
    def get_Associated_Code(self): return self.Associated_Code
    def set_Associated_Code(self, Associated_Code): self.Associated_Code = Associated_Code
    def get_Relationships(self): return self.Relationships
    def set_Relationships(self, Relationships): self.Relationships = Relationships
    def get_status(self): return self.status
    def set_status(self, status): self.status = status
    def get_duration(self): return self.duration
    def set_duration(self, duration): self.duration = duration
    def get_ordinal_position(self): return self.ordinal_position
    def set_ordinal_position(self, ordinal_position): self.ordinal_position = ordinal_position
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Purpose is not None or
            self.Description is not None or
            self.Discovery_Method is not None or
            self.Action_Composition is not None or
            self.Associated_Code is not None or
            self.Relationships is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorType'):
        if self.status is not None and 'status' not in already_processed:
            already_processed.add('status')
            write(' status=%s' % (quote_attrib(self.status), ))
        if self.duration is not None and 'duration' not in already_processed:
            already_processed.add('duration')
            write(' duration=%s' % (quote_attrib(self.duration).encode(ExternalEncoding)))
        if self.ordinal_position is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            write(' ordinal_position="%s"' % self.gds_format_integer(self.ordinal_position, input_name='ordinal_position'))
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Purpose is not None:
            self.Purpose.export(write, level, 'maecBundle:', name_='Purpose', pretty_print=pretty_print)
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
        if self.Discovery_Method is not None:
            self.Discovery_Method.export(write, level, 'maecBundle:', name_='Discovery_Method', pretty_print=pretty_print)
        if self.Action_Composition is not None:
            self.Action_Composition.export(write, level, 'maecBundle:', name_='Action_Composition', pretty_print=pretty_print)
        if self.Associated_Code is not None:
            self.Associated_Code.export(write, level, 'maecBundle:', name_='Associated_Code', pretty_print=pretty_print)
        if self.Relationships is not None:
            self.Relationships.export(write, level, 'maecBundle:', name_='Relationships', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('status', node)
        if value is not None and 'status' not in already_processed:
            already_processed.add('status')
            self.status = value
        value = find_attr_value_('duration', node)
        if value is not None and 'duration' not in already_processed:
            already_processed.add('duration')
            self.duration = value
        value = find_attr_value_('ordinal_position', node)
        if value is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            try:
                self.ordinal_position = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
            if self.ordinal_position <= 0:
                raise_parse_error(node, 'Invalid PositiveInteger')
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Purpose':
            obj_ = BehaviorPurposeType.factory()
            obj_.build(child_)
            self.set_Purpose(obj_)
        elif nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
        elif nodeName_ == 'Discovery_Method':
            obj_ = cybox_common.MeasureSourceType.factory()
            obj_.build(child_)
            self.set_Discovery_Method(obj_)
        elif nodeName_ == 'Action_Composition':
            obj_ = BehavioralActionsType.factory()
            obj_.build(child_)
            self.set_Action_Composition(obj_)
        elif nodeName_ == 'Associated_Code':
            obj_ = AssociatedCodeType.factory()
            obj_.build(child_)
            self.set_Associated_Code(obj_)
        elif nodeName_ == 'Relationships':
            obj_ = BehaviorRelationshipListType.factory()
            obj_.build(child_)
            self.set_Relationships(obj_)
# end class BehaviorType

class BundleType(GeneratedsSuper):
    """The BundleType serves as the high-level construct which encapsulates
    all Bundle elements, and represents some characterized analysis
    data (from any arbitrary set of analyses) for a single malware
    instance in terms of its MAEC Components (e.g., Behaviors,
    Actions, Objects, etc.).The required id field specifies a unique
    ID for this MAEC Bundle. The required schema_version field
    specifies the version of the MAEC Bundle Schema that the
    document has been written in and that should be used for
    validation.The required defined_subject field specifies whether
    the subject attributes of the characterized malware instance are
    included inside this Bundle (via the top-level
    Malware_Instance_Object_Attributes field) or elsewhere (such as
    a MAEC Subject in a MAEC Package).The content_type field
    specifies the general type of content contained in this Bundle,
    e.g. static analysis tool output, dynamic analysis tool output,
    etc.The timestamp field specifies the date/time that the bundle
    was generated."""
    subclass = None
    superclass = None
    def __init__(self, defined_subject=None, content_type=None, id=None, schema_version=None, timestamp=None, Malware_Instance_Object_Attributes=None, AV_Classifications=None, Process_Tree=None, Capabilities=None, Behaviors=None, Actions=None, Objects=None, Candidate_Indicators=None, Collections=None):
        self.defined_subject = _cast(bool, defined_subject)
        self.content_type = _cast(None, content_type)
        self.id = _cast(None, id)
        self.schema_version = _cast(None, schema_version)
        self.timestamp = _cast(None, timestamp)
        self.Malware_Instance_Object_Attributes = Malware_Instance_Object_Attributes
        self.AV_Classifications = AV_Classifications
        self.Process_Tree = Process_Tree
        self.Capabilities = Capabilities
        self.Behaviors = Behaviors
        self.Actions = Actions
        self.Objects = Objects
        self.Candidate_Indicators = Candidate_Indicators
        self.Collections = Collections
    def factory(*args_, **kwargs_):
        if BundleType.subclass:
            return BundleType.subclass(*args_, **kwargs_)
        else:
            return BundleType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Malware_Instance_Object_Attributes(self): return self.Malware_Instance_Object_Attributes
    def set_Malware_Instance_Object_Attributes(self, Malware_Instance_Object_Attributes): self.Malware_Instance_Object_Attributes = Malware_Instance_Object_Attributes
    def get_AV_Classifications(self): return self.AV_Classifications
    def set_AV_Classifications(self, AV_Classifications): self.AV_Classifications = AV_Classifications
    def get_Process_Tree(self): return self.Process_Tree
    def set_Process_Tree(self, Process_Tree): self.Process_Tree = Process_Tree
    def get_Capabilities(self): return self.Capabilities
    def set_Capabilities(self, Capabilities): self.Capabilities = Capabilities
    def get_Behaviors(self): return self.Behaviors
    def set_Behaviors(self, Behaviors): self.Behaviors = Behaviors
    def get_Actions(self): return self.Actions
    def set_Actions(self, Actions): self.Actions = Actions
    def get_Objects(self): return self.Objects
    def set_Objects(self, Objects): self.Objects = Objects
    def get_Candidate_Indicators(self): return self.Candidate_Indicators
    def set_Candidate_Indicators(self, Candidate_Indicators): self.Candidate_Indicators = Candidate_Indicators
    def get_Collections(self): return self.Collections
    def set_Collections(self, Collections): self.Collections = Collections
    def get_defined_subject(self): return self.defined_subject
    def set_defined_subject(self, defined_subject): self.defined_subject = defined_subject
    def get_content_type(self): return self.content_type
    def set_content_type(self, content_type): self.content_type = content_type
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def get_schema_version(self): return self.schema_version
    def set_schema_version(self, schema_version): self.schema_version = schema_version
    def get_timestamp(self): return self.timestamp
    def set_timestamp(self, timestamp): self.timestamp = timestamp
    def hasContent_(self):
        if (
            self.Malware_Instance_Object_Attributes is not None or
            self.AV_Classifications is not None or
            self.Process_Tree is not None or
            self.Capabilities is not None or
            self.Behaviors is not None or
            self.Actions is not None or
            self.Objects is not None or
            self.Candidate_Indicators is not None or
            self.Collections is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='MAEC_Bundle', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MAEC_Bundle')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='MAEC_Bundle'):
        if self.defined_subject is not None and 'defined_subject' not in already_processed:
            already_processed.add('defined_subject')
            write(' defined_subject="%s"' % self.gds_format_boolean(self.defined_subject, input_name='defined_subject'))
        if self.content_type is not None and 'content_type' not in already_processed:
            already_processed.add('content_type')
            write(' content_type=%s' % (quote_attrib(self.content_type), ))
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
        if self.schema_version is not None and 'schema_version' not in already_processed:
            already_processed.add('schema_version')
            write(' schema_version=%s' % (quote_attrib(self.schema_version)))
        if self.timestamp is not None and 'timestamp' not in already_processed:
            already_processed.add('timestamp')
            write(' timestamp="%s"' % self.gds_format_datetime(self.timestamp, input_name='timestamp'))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='MAEC_Bundle', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Malware_Instance_Object_Attributes is not None:
            self.Malware_Instance_Object_Attributes.export(write, level, 'maecBundle:', name_='Malware_Instance_Object_Attributes', pretty_print=pretty_print)
        if self.AV_Classifications is not None:
            self.AV_Classifications.export(write, level, 'maecBundle:', name_='AV_Classifications', pretty_print=pretty_print)
        if self.Process_Tree is not None:
            self.Process_Tree.export(write, level, 'maecBundle:', name_='Process_Tree', pretty_print=pretty_print)
        if self.Capabilities is not None:
            self.Capabilities.export(write, level, 'maecBundle:', name_='Capabilities', pretty_print=pretty_print)
        if self.Behaviors is not None:
            self.Behaviors.export(write, level, 'maecBundle:', name_='Behaviors', pretty_print=pretty_print)
        if self.Actions is not None:
            self.Actions.export(write, level, 'maecBundle:', name_='Actions', pretty_print=pretty_print)
        if self.Objects is not None:
            self.Objects.export(write, level, 'maecBundle:', name_='Objects', pretty_print=pretty_print)
        if self.Candidate_Indicators is not None:
            self.Candidate_Indicators.export(write, level, 'maecBundle:', name_='Candidate_Indicators', pretty_print=pretty_print)
        if self.Collections is not None:
            self.Collections.export(write, level, 'maecBundle:', name_='Collections', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('defined_subject', node)
        if value is not None and 'defined_subject' not in already_processed:
            already_processed.add('defined_subject')
            if value in ('true', '1'):
                self.defined_subject = True
            elif value in ('false', '0'):
                self.defined_subject = False
            else:
                raise_parse_error(node, 'Bad boolean attribute')
        value = find_attr_value_('content_type', node)
        if value is not None and 'content_type' not in already_processed:
            already_processed.add('content_type')
            self.content_type = value
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
        value = find_attr_value_('schema_version', node)
        if value is not None and 'schema_version' not in already_processed:
            already_processed.add('schema_version')
            self.schema_version = value
        value = find_attr_value_('timestamp', node)
        if value is not None and 'timestamp' not in already_processed:
            already_processed.add('timestamp')
            try:
                self.timestamp = self.gds_parse_datetime(value, node, 'timestamp')
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (timestamp): %s' % exp)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Malware_Instance_Object_Attributes':
            obj_ = cybox_core.ObjectType.factory()
            obj_.build(child_)
            self.set_Malware_Instance_Object_Attributes(obj_)
        elif nodeName_ == 'AV_Classifications':
            obj_ = AVClassificationsType.factory()
            obj_.build(child_)
            self.set_AV_Classifications(obj_)
        elif nodeName_ == 'Process_Tree':
            obj_ = ProcessTreeType.factory()
            obj_.build(child_)
            self.set_Process_Tree(obj_)
        elif nodeName_ == 'Capabilities':
            obj_ = CapabilityListType.factory()
            obj_.build(child_)
            self.set_Capabilities(obj_)
        elif nodeName_ == 'Behaviors':
            obj_ = BehaviorListType.factory()
            obj_.build(child_)
            self.set_Behaviors(obj_)
        elif nodeName_ == 'Actions':
            obj_ = ActionListType.factory()
            obj_.build(child_)
            self.set_Actions(obj_)
        elif nodeName_ == 'Objects':
            obj_ = ObjectListType.factory()
            obj_.build(child_)
            self.set_Objects(obj_)
        elif nodeName_ == 'Candidate_Indicators':
            obj_ = CandidateIndicatorListType.factory()
            obj_.build(child_)
            self.set_Candidate_Indicators(obj_)
        elif nodeName_ == 'Collections':
            obj_ = CollectionsType.factory()
            obj_.build(child_)
            self.set_Collections(obj_)
# end class BundleType

class APICallType(GeneratedsSuper):
    """The APICallType provides a method for the characterization of API
    calls, including functions and their parameters.The
    function_name field contains the exact name of the API function
    called, e.g. CreateFileEx.The normalized_function_name field
    contains the normalized name of the API function called, e.g.
    CreateFile."""
    subclass = None
    superclass = None
    def __init__(self, normalized_function_name=None, function_name=None, Address=None, Return_Value=None, Parameters=None):
        self.normalized_function_name = _cast(None, normalized_function_name)
        self.function_name = _cast(None, function_name)
        self.Address = Address
        self.Return_Value = Return_Value
        self.Parameters = Parameters
    def factory(*args_, **kwargs_):
        if APICallType.subclass:
            return APICallType.subclass(*args_, **kwargs_)
        else:
            return APICallType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Address(self): return self.Address
    def set_Address(self, Address): self.Address = Address
    def get_Return_Value(self): return self.Return_Value
    def set_Return_Value(self, Return_Value): self.Return_Value = Return_Value
    def get_Parameters(self): return self.Parameters
    def set_Parameters(self, Parameters): self.Parameters = Parameters
    def get_normalized_function_name(self): return self.normalized_function_name
    def set_normalized_function_name(self, normalized_function_name): self.normalized_function_name = normalized_function_name
    def get_function_name(self): return self.function_name
    def set_function_name(self, function_name): self.function_name = function_name
    def hasContent_(self):
        if (
            self.Address is not None or
            self.Return_Value is not None or
            self.Parameters is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='APICallType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='APICallType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='APICallType'):
        if self.normalized_function_name is not None and 'normalized_function_name' not in already_processed:
            already_processed.add('normalized_function_name')
            write(' normalized_function_name=%s' % (quote_attrib(self.normalized_function_name)))
        if self.function_name is not None and 'function_name' not in already_processed:
            already_processed.add('function_name')
            write(' function_name=%s' % (quote_attrib(self.function_name)))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='APICallType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Address is not None:
            showIndent(write, level, pretty_print)
            write('<%sAddress>%s</%sAddress>%s' % ('maecBundle:', quote_xml(self.Address), 'maecBundle:', eol_))
        if self.Return_Value is not None:
            showIndent(write, level, pretty_print)
            write('<%sReturn_Value>%s</%sReturn_Value>%s' % ('maecBundle:', quote_xml(self.Return_Value), 'maecBundle:', eol_))
        if self.Parameters is not None:
            self.Parameters.export(write, level, 'maecBundle:', name_='Parameters', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('normalized_function_name', node)
        if value is not None and 'normalized_function_name' not in already_processed:
            already_processed.add('normalized_function_name')
            self.normalized_function_name = value
        value = find_attr_value_('function_name', node)
        if value is not None and 'function_name' not in already_processed:
            already_processed.add('function_name')
            self.function_name = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Address':
            Address_ = child_.text
            Address_ = self.gds_validate_string(Address_, node, 'Address')
            self.Address = Address_
        elif nodeName_ == 'Return_Value':
            Return_Value_ = child_.text
            Return_Value_ = self.gds_validate_string(Return_Value_, node, 'Return_Value')
            self.Return_Value = Return_Value_
        elif nodeName_ == 'Parameters':
            obj_ = ParameterListType.factory()
            obj_.build(child_)
            self.set_Parameters(obj_)
# end class APICallType

class ActionImplementationType(GeneratedsSuper):
    """The ActionImplementationType serves as a method for the
    characterization of Action Implementations. Currently supported
    are implementations achieved through API function calls and
    abstractly defined code. The id field specifies a unique ID for
    this Action Implementation. The ID must follow the pattern
    defined in the ActionImpIDPattern simple type. The required type
    field refers to the type of Action Implementation being
    characterized in this element."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, id=None, Compatible_Platforms=None, API_Call=None, Code=None):
        self.type_ = _cast(None, type_)
        self.id = _cast(None, id)
        self.Compatible_Platforms = Compatible_Platforms
        self.API_Call = API_Call
        if Code is None:
            self.Code = []
        else:
            self.Code = Code
    def factory(*args_, **kwargs_):
        if ActionImplementationType.subclass:
            return ActionImplementationType.subclass(*args_, **kwargs_)
        else:
            return ActionImplementationType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Compatible_Platforms(self): return self.Compatible_Platforms
    def set_Compatible_Platforms(self, Compatible_Platforms): self.Compatible_Platforms = Compatible_Platforms
    def get_API_Call(self): return self.API_Call
    def set_API_Call(self, API_Call): self.API_Call = API_Call
    def get_Code(self): return self.Code
    def set_Code(self, Code): self.Code = Code
    def add_Code(self, value): self.Code.append(value)
    def insert_Code(self, index, value): self.Code[index] = value
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Compatible_Platforms is not None or
            self.API_Call is not None or
            self.Code
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ActionImplementationType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ActionImplementationType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ActionImplementationType'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.add('type_')
            write(' type=%s' % (quote_attrib(self.type_), ))
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ActionImplementationType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Compatible_Platforms is not None:
            self.Compatible_Platforms.export(write, level, 'maecBundle:', name_='Compatible_Platforms', pretty_print=pretty_print)
        if self.API_Call is not None:
            self.API_Call.export(write, level, 'maecBundle:', name_='API_Call', pretty_print=pretty_print)
        for Code_ in self.Code:
            Code_.export(write, level, 'maecBundle:', name_='Code', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.add('type')
            self.type_ = value
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Compatible_Platforms':
            obj_ = PlatformListType.factory()
            obj_.build(child_)
            self.set_Compatible_Platforms(obj_)
        elif nodeName_ == 'API_Call':
            obj_ = APICallType.factory()
            obj_.build(child_)
            self.set_API_Call(obj_)
        elif nodeName_ == 'Code':
            obj_ = code_object.CodeObjectType.factory()
            obj_.build(child_)
            self.Code.append(obj_)
# end class ActionImplementationType

class CVEVulnerabilityType(GeneratedsSuper):
    """The CVEVulnerabilityType provides a way of referencing specific
    vulnerabilities that malware exploits or attempts to exploit via
    a Common Vulnerabilities and Exposures (CVE) identifier. For
    more information on CVE please see http://cve.mitre.org. The
    cve_id attribute contains the ID of the CVE that is being
    referenced, e.g., CVE-1999-0002."""
    subclass = None
    superclass = None
    def __init__(self, cve_id=None, Description=None):
        self.cve_id = _cast(None, cve_id)
        self.Description = Description
    def factory(*args_, **kwargs_):
        if CVEVulnerabilityType.subclass:
            return CVEVulnerabilityType.subclass(*args_, **kwargs_)
        else:
            return CVEVulnerabilityType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_cve_id(self): return self.cve_id
    def set_cve_id(self, cve_id): self.cve_id = cve_id
    def hasContent_(self):
        if (
            self.Description is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CVEVulnerabilityType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CVEVulnerabilityType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CVEVulnerabilityType'):
        if self.cve_id is not None and 'cve_id' not in already_processed:
            already_processed.add('cve_id')
            write(' cve_id=%s' % (quote_attrib(self.cve_id)))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CVEVulnerabilityType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('cve_id', node)
        if value is not None and 'cve_id' not in already_processed:
            already_processed.add('cve_id')
            self.cve_id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
# end class CVEVulnerabilityType

class BaseCollectionType(GeneratedsSuper):
    """The BaseCollectionType is the base type for other MAEC collection
    types.The name field specifies the name of the collection."""
    subclass = None
    superclass = None
    def __init__(self, name=None, Affinity_Type=None, Affinity_Degree=None, Description=None, extensiontype_=None):
        self.name = _cast(None, name)
        self.Affinity_Type = Affinity_Type
        self.Affinity_Degree = Affinity_Degree
        self.Description = Description
        self.extensiontype_ = extensiontype_
    def factory(*args_, **kwargs_):
        if BaseCollectionType.subclass:
            return BaseCollectionType.subclass(*args_, **kwargs_)
        else:
            return BaseCollectionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Affinity_Type(self): return self.Affinity_Type
    def set_Affinity_Type(self, Affinity_Type): self.Affinity_Type = Affinity_Type
    def get_Affinity_Degree(self): return self.Affinity_Degree
    def set_Affinity_Degree(self, Affinity_Degree): self.Affinity_Degree = Affinity_Degree
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_name(self): return self.name
    def set_name(self, name): self.name = name
    def get_extensiontype_(self): return self.extensiontype_
    def set_extensiontype_(self, extensiontype_): self.extensiontype_ = extensiontype_
    def hasContent_(self):
        if (
            self.Affinity_Type is not None or
            self.Affinity_Degree is not None or
            self.Description is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BaseCollectionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BaseCollectionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BaseCollectionType'):
        if self.name is not None and 'name' not in already_processed:
            already_processed.add('name')
            write(' name=%s' % (quote_attrib(self.name)))
        if self.extensiontype_ is not None and 'xsi:type' not in already_processed:
            already_processed.add('xsi:type')
            write(' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')
            write(' xsi:type="%s"' % self.extensiontype_)
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BaseCollectionType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Affinity_Type is not None:
            showIndent(write, level, pretty_print)
            write('<%sAffinity_Type>%s</%sAffinity_Type>%s' % ('maecBundle:', quote_xml(self.Affinity_Type), 'maecBundle:', eol_))
        if self.Affinity_Degree is not None:
            showIndent(write, level, pretty_print)
            write('<%sAffinity_Degree>%s</%sAffinity_Degree>%s' % ('maecBundle:', quote_xml(self.Affinity_Degree), 'maecBundle:', eol_))
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('name', node)
        if value is not None and 'name' not in already_processed:
            already_processed.add('name')
            self.name = value
        value = find_attr_value_('xsi:type', node)
        if value is not None and 'xsi:type' not in already_processed:
            already_processed.add('xsi:type')
            self.extensiontype_ = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Affinity_Type':
            Affinity_Type_ = child_.text
            Affinity_Type_ = self.gds_validate_string(Affinity_Type_, node, 'Affinity_Type')
            self.Affinity_Type = Affinity_Type_
        elif nodeName_ == 'Affinity_Degree':
            Affinity_Degree_ = child_.text
            Affinity_Degree_ = self.gds_validate_string(Affinity_Degree_, node, 'Affinity_Degree')
            self.Affinity_Degree = Affinity_Degree_
        elif nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
# end class BaseCollectionType

class BehaviorRelationshipType(GeneratedsSuper):
    """The BehaviorRelationshipType provides a method for the
    characterization of relationships between Behaviors. The type
    field specifies the nature of the relationship between Behaviors
    that is being captured."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, Behavior_Reference=None):
        self.type_ = _cast(None, type_)
        if Behavior_Reference is None:
            self.Behavior_Reference = []
        else:
            self.Behavior_Reference = Behavior_Reference
    def factory(*args_, **kwargs_):
        if BehaviorRelationshipType.subclass:
            return BehaviorRelationshipType.subclass(*args_, **kwargs_)
        else:
            return BehaviorRelationshipType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Behavior_Reference(self): return self.Behavior_Reference
    def set_Behavior_Reference(self, Behavior_Reference): self.Behavior_Reference = Behavior_Reference
    def add_Behavior_Reference(self, value): self.Behavior_Reference.append(value)
    def insert_Behavior_Reference(self, index, value): self.Behavior_Reference[index] = value
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def hasContent_(self):
        if (
            self.Behavior_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorRelationshipType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorRelationshipType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorRelationshipType'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.add('type_')
            write(' type=%s' % (quote_attrib(self.type_), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorRelationshipType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Behavior_Reference_ in self.Behavior_Reference:
            Behavior_Reference_.export(write, level, 'maecBundle:', name_='Behavior_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.add('type')
            self.type_ = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Behavior_Reference':
            obj_ = BehaviorReferenceType.factory()
            obj_.build(child_)
            self.Behavior_Reference.append(obj_)
# end class BehaviorRelationshipType

class AVClassificationsType(GeneratedsSuper):
    """The AVClassificationsType captures any Anti-Virus (AV) tool
    classifications for an Object."""
    subclass = None
    superclass = None
    def __init__(self, AV_Classification=None):
        if AV_Classification is None:
            self.AV_Classification = []
        else:
            self.AV_Classification = AV_Classification
    def factory(*args_, **kwargs_):
        if AVClassificationsType.subclass:
            return AVClassificationsType.subclass(*args_, **kwargs_)
        else:
            return AVClassificationsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_AV_Classification(self): return self.AV_Classification
    def set_AV_Classification(self, AV_Classification): self.AV_Classification = AV_Classification
    def add_AV_Classification(self, value): self.AV_Classification.append(value)
    def insert_AV_Classification(self, index, value): self.AV_Classification[index] = value
    def hasContent_(self):
        if (
            self.AV_Classification
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='AVClassificationsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AVClassificationsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='AVClassificationsType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='AVClassificationsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for AV_Classification_ in self.AV_Classification:
            AV_Classification_.export(write, level, 'maecBundle:', name_='AV_Classification', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'AV_Classification':
            obj_ = AVClassificationType.factory()
            obj_.build(child_)
            self.AV_Classification.append(obj_)
# end class AVClassificationsType

class ParameterType(GeneratedsSuper):
    """The ParameterType characterizes function parameters.This field
    refers to the ordinal position of the parameter with respect to
    the function where it is used.The name field specifies the name
    of the parameter.The value field specifies the actual value of
    the parameter."""
    subclass = None
    superclass = None
    def __init__(self, ordinal_position=None, name=None, value=None):
        self.ordinal_position = _cast(int, ordinal_position)
        self.name = _cast(None, name)
        self.value = _cast(None, value)
        pass
    def factory(*args_, **kwargs_):
        if ParameterType.subclass:
            return ParameterType.subclass(*args_, **kwargs_)
        else:
            return ParameterType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_ordinal_position(self): return self.ordinal_position
    def set_ordinal_position(self, ordinal_position): self.ordinal_position = ordinal_position
    def get_name(self): return self.name
    def set_name(self, name): self.name = name
    def get_value(self): return self.value
    def set_value(self, value): self.value = value
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ParameterType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ParameterType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ParameterType'):
        if self.ordinal_position is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            write(' ordinal_position="%s"' % self.gds_format_integer(self.ordinal_position, input_name='ordinal_position'))
        if self.name is not None and 'name' not in already_processed:
            already_processed.add('name')
            write(' name=%s' % (quote_attrib(self.name)))
        if self.value is not None and 'value' not in already_processed:
            already_processed.add('value')
            write(' value=%s' % (quote_attrib(self.value)))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ParameterType', fromsubclass_=False, pretty_print=True):
        pass
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
        value = find_attr_value_('name', node)
        if value is not None and 'name' not in already_processed:
            already_processed.add('name')
            self.name = value
        value = find_attr_value_('value', node)
        if value is not None and 'value' not in already_processed:
            already_processed.add('value')
            self.value = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class ParameterType

class ParameterListType(GeneratedsSuper):
    """The ParametersType captures a list of function parameters."""
    subclass = None
    superclass = None
    def __init__(self, Parameter=None):
        if Parameter is None:
            self.Parameter = []
        else:
            self.Parameter = Parameter
    def factory(*args_, **kwargs_):
        if ParameterListType.subclass:
            return ParameterListType.subclass(*args_, **kwargs_)
        else:
            return ParameterListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Parameter(self): return self.Parameter
    def set_Parameter(self, Parameter): self.Parameter = Parameter
    def add_Parameter(self, value): self.Parameter.append(value)
    def insert_Parameter(self, index, value): self.Parameter[index] = value
    def hasContent_(self):
        if (
            self.Parameter
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ParameterListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ParameterListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ParameterListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ParameterListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Parameter_ in self.Parameter:
            Parameter_.export(write, level, 'maecBundle:', name_='Parameter', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Parameter':
            obj_ = ParameterType.factory()
            obj_.build(child_)
            self.Parameter.append(obj_)
# end class ParameterListType

class AssociatedCodeType(GeneratedsSuper):
    """The AssociatedCodeType serves as generic way of specifying any code
    snippets associated with a MAEC entity, such as a Behavior."""
    subclass = None
    superclass = None
    def __init__(self, Code_Snippet=None):
        if Code_Snippet is None:
            self.Code_Snippet = []
        else:
            self.Code_Snippet = Code_Snippet
    def factory(*args_, **kwargs_):
        if AssociatedCodeType.subclass:
            return AssociatedCodeType.subclass(*args_, **kwargs_)
        else:
            return AssociatedCodeType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Code_Snippet(self): return self.Code_Snippet
    def set_Code_Snippet(self, Code_Snippet): self.Code_Snippet = Code_Snippet
    def add_Code_Snippet(self, value): self.Code_Snippet.append(value)
    def insert_Code_Snippet(self, index, value): self.Code_Snippet[index] = value
    def hasContent_(self):
        if (
            self.Code_Snippet
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='AssociatedCodeType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AssociatedCodeType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='AssociatedCodeType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='AssociatedCodeType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Code_Snippet_ in self.Code_Snippet:
            Code_Snippet_.export(write, level, 'maecBundle:', name_='Code_Snippet', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Code_Snippet':
            obj_ = code_object.CodeObjectType.factory()
            obj_.build(child_)
            self.Code_Snippet.append(obj_)
# end class AssociatedCodeType

class BehaviorPurposeType(GeneratedsSuper):
    """The BehaviorPurposeType captures the purpose behind a malware
    Behavior."""
    subclass = None
    superclass = None
    def __init__(self, Description=None, Vulnerability_Exploit=None):
        self.Description = Description
        self.Vulnerability_Exploit = Vulnerability_Exploit
    def factory(*args_, **kwargs_):
        if BehaviorPurposeType.subclass:
            return BehaviorPurposeType.subclass(*args_, **kwargs_)
        else:
            return BehaviorPurposeType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_Vulnerability_Exploit(self): return self.Vulnerability_Exploit
    def set_Vulnerability_Exploit(self, Vulnerability_Exploit): self.Vulnerability_Exploit = Vulnerability_Exploit
    def hasContent_(self):
        if (
            self.Description is not None or
            self.Vulnerability_Exploit is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorPurposeType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorPurposeType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorPurposeType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorPurposeType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
        if self.Vulnerability_Exploit is not None:
            self.Vulnerability_Exploit.export(write, level, 'maecBundle:', name_='Vulnerability_Exploit', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
        elif nodeName_ == 'Vulnerability_Exploit':
            obj_ = ExploitType.factory()
            obj_.build(child_)
            self.set_Vulnerability_Exploit(obj_)
# end class BehaviorPurposeType

class PlatformListType(GeneratedsSuper):
    """The PlatformListType captures a list of software or hardware
    platforms."""
    subclass = None
    superclass = None
    def __init__(self, Platform=None):
        if Platform is None:
            self.Platform = []
        else:
            self.Platform = Platform
    def factory(*args_, **kwargs_):
        if PlatformListType.subclass:
            return PlatformListType.subclass(*args_, **kwargs_)
        else:
            return PlatformListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Platform(self): return self.Platform
    def set_Platform(self, Platform): self.Platform = Platform
    def add_Platform(self, value): self.Platform.append(value)
    def insert_Platform(self, index, value): self.Platform[index] = value
    def hasContent_(self):
        if (
            self.Platform
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='PlatformListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='PlatformListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='PlatformListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='PlatformListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Platform_ in self.Platform:
            Platform_.export(write, level, 'maecBundle:', name_='Platform', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Platform':
            obj_ = cybox_common.PlatformSpecificationType.factory()
            obj_.build(child_)
            self.Platform.append(obj_)
# end class PlatformListType

class ExploitType(GeneratedsSuper):
    """The ExploitType characterizes any exploitable weakness that may be
    targeted for exploitation by a malware instance through a
    Behavior. Most commonly, this refers to a known and identifiable
    vulnerability, but it may also refer to one or more
    weaknesses.The known_vulnerability field specifies whether the
    vulnerability that the malware is exploiting has been previously
    identified. If so, it should be referenced via a CVE ID in the
    CVE element. If not, the platform(s) targeted by the
    vulnerability exploitation behavior may be specified in the
    Targeted_Platforms element."""
    subclass = None
    superclass = None
    def __init__(self, known_vulnerability=None, CVE=None, CWE_ID=None, Targeted_Platforms=None):
        self.known_vulnerability = _cast(bool, known_vulnerability)
        self.CVE = CVE
        if CWE_ID is None:
            self.CWE_ID = []
        else:
            self.CWE_ID = CWE_ID
        self.Targeted_Platforms = Targeted_Platforms
    def factory(*args_, **kwargs_):
        if ExploitType.subclass:
            return ExploitType.subclass(*args_, **kwargs_)
        else:
            return ExploitType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_CVE(self): return self.CVE
    def set_CVE(self, CVE): self.CVE = CVE
    def get_CWE_ID(self): return self.CWE_ID
    def set_CWE_ID(self, CWE_ID): self.CWE_ID = CWE_ID
    def add_CWE_ID(self, value): self.CWE_ID.append(value)
    def insert_CWE_ID(self, index, value): self.CWE_ID[index] = value
    def get_Targeted_Platforms(self): return self.Targeted_Platforms
    def set_Targeted_Platforms(self, Targeted_Platforms): self.Targeted_Platforms = Targeted_Platforms
    def get_known_vulnerability(self): return self.known_vulnerability
    def set_known_vulnerability(self, known_vulnerability): self.known_vulnerability = known_vulnerability
    def hasContent_(self):
        if (
            self.CVE is not None or
            self.CWE_ID or
            self.Targeted_Platforms is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ExploitType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ExploitType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ExploitType'):
        if self.known_vulnerability is not None and 'known_vulnerability' not in already_processed:
            already_processed.add('known_vulnerability')
            write(' known_vulnerability="%s"' % self.gds_format_boolean(self.known_vulnerability, input_name='known_vulnerability'))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ExploitType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.CVE is not None:
            self.CVE.export(write, level, 'maecBundle:', name_='CVE', pretty_print=pretty_print)
        for CWE_ID_ in self.CWE_ID:
            showIndent(write, level, pretty_print)
            write('<%sCWE_ID>%s</%sCWE_ID>%s' % ('maecBundle:', quote_xml(CWE_ID_), 'maecBundle:', eol_))
        if self.Targeted_Platforms is not None:
            self.Targeted_Platforms.export(write, level, 'maecBundle:', name_='Targeted_Platforms', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('known_vulnerability', node)
        if value is not None and 'known_vulnerability' not in already_processed:
            already_processed.add('known_vulnerability')
            if value in ('true', '1'):
                self.known_vulnerability = True
            elif value in ('false', '0'):
                self.known_vulnerability = False
            else:
                raise_parse_error(node, 'Bad boolean attribute')
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'CVE':
            obj_ = CVEVulnerabilityType.factory()
            obj_.build(child_)
            self.set_CVE(obj_)
        elif nodeName_ == 'CWE_ID':
            CWE_ID_ = child_.text
            CWE_ID_ = self.gds_validate_string(CWE_ID_, node, 'CWE_ID')
            self.CWE_ID.append(CWE_ID_)
        elif nodeName_ == 'Targeted_Platforms':
            obj_ = PlatformListType.factory()
            obj_.build(child_)
            self.set_Targeted_Platforms(obj_)
# end class ExploitType

class BehaviorRelationshipListType(GeneratedsSuper):
    """The BehaviorRelationshipListType captures any relationships between
    a Behavior and other Behaviors."""
    subclass = None
    superclass = None
    def __init__(self, Relationship=None):
        if Relationship is None:
            self.Relationship = []
        else:
            self.Relationship = Relationship
    def factory(*args_, **kwargs_):
        if BehaviorRelationshipListType.subclass:
            return BehaviorRelationshipListType.subclass(*args_, **kwargs_)
        else:
            return BehaviorRelationshipListType(*args_, **kwargs_)
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
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorRelationshipListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorRelationshipListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorRelationshipListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorRelationshipListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Relationship_ in self.Relationship:
            Relationship_.export(write, level, 'maecBundle:', name_='Relationship', pretty_print=pretty_print)
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
            obj_ = BehaviorRelationshipType.factory()
            obj_.build(child_)
            self.Relationship.append(obj_)
# end class BehaviorRelationshipListType

class BehavioralActionsType(GeneratedsSuper):
    """The BehavioralActionsType is intended to capture the Actions or
    Action Collections that make up a Behavior."""
    subclass = None
    superclass = None
    def __init__(self, Action_Collection=None, Action=None, Action_Reference=None, Action_Equivalence_Reference=None):
        if Action_Collection is None:
            self.Action_Collection = []
        else:
            self.Action_Collection = Action_Collection
        if Action is None:
            self.Action = []
        else:
            self.Action = Action
        if Action_Reference is None:
            self.Action_Reference = []
        else:
            self.Action_Reference = Action_Reference
        if Action_Equivalence_Reference is None:
            self.Action_Equivalence_Reference = []
        else:
            self.Action_Equivalence_Reference = Action_Equivalence_Reference
    def factory(*args_, **kwargs_):
        if BehavioralActionsType.subclass:
            return BehavioralActionsType.subclass(*args_, **kwargs_)
        else:
            return BehavioralActionsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action_Collection(self): return self.Action_Collection
    def set_Action_Collection(self, Action_Collection): self.Action_Collection = Action_Collection
    def add_Action_Collection(self, value): self.Action_Collection.append(value)
    def insert_Action_Collection(self, index, value): self.Action_Collection[index] = value
    def get_Action(self): return self.Action
    def set_Action(self, Action): self.Action = Action
    def add_Action(self, value): self.Action.append(value)
    def insert_Action(self, index, value): self.Action[index] = value
    def get_Action_Reference(self): return self.Action_Reference
    def set_Action_Reference(self, Action_Reference): self.Action_Reference = Action_Reference
    def add_Action_Reference(self, value): self.Action_Reference.append(value)
    def insert_Action_Reference(self, index, value): self.Action_Reference[index] = value
    def get_Action_Equivalence_Reference(self): return self.Action_Equivalence_Reference
    def set_Action_Equivalence_Reference(self, Action_Equivalence_Reference): self.Action_Equivalence_Reference = Action_Equivalence_Reference
    def add_Action_Equivalence_Reference(self, value): self.Action_Equivalence_Reference.append(value)
    def insert_Action_Equivalence_Reference(self, index, value): self.Action_Equivalence_Reference[index] = value
    def hasContent_(self):
        if (
            self.Action_Collection or
            self.Action or
            self.Action_Reference or
            self.Action_Equivalence_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehavioralActionsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehavioralActionsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehavioralActionsType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehavioralActionsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Action_Collection_ in self.Action_Collection:
            Action_Collection_.export(write, level, 'maecBundle:', name_='Action_Collection', pretty_print=pretty_print)
        for Action_ in self.Action:
            Action_.export(write, level, 'maecBundle:', name_='Action', pretty_print=pretty_print)
        for Action_Reference_ in self.Action_Reference:
            Action_Reference_.export(write, level, 'maecBundle:', name_='Action_Reference', pretty_print=pretty_print)
        for Action_Equivalence_Reference_ in self.Action_Equivalence_Reference:
            Action_Equivalence_Reference_.export(write, level, 'maecBundle:', name_='Action_Equivalence_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action_Collection':
            obj_ = ActionCollectionType.factory()
            obj_.build(child_)
            self.Action_Collection.append(obj_)
        elif nodeName_ == 'Action':
            obj_ = MalwareActionType.factory()
            obj_.build(child_)
            self.Action.append(obj_)
        elif nodeName_ == 'Action_Reference':
            obj_ = BehavioralActionReferenceType.factory()
            obj_.build(child_)
            self.Action_Reference.append(obj_)
        elif nodeName_ == 'Action_Equivalence_Reference':
            obj_ = BehavioralActionEquivalenceReferenceType.factory()
            obj_.build(child_)
            self.Action_Equivalence_Reference.append(obj_)
# end class BehavioralActionsType

class BehaviorListType(GeneratedsSuper):
    """The BehaviorListType captures a list of Behaviors."""
    subclass = None
    superclass = None
    def __init__(self, Behavior=None):
        if Behavior is None:
            self.Behavior = []
        else:
            self.Behavior = Behavior
    def factory(*args_, **kwargs_):
        if BehaviorListType.subclass:
            return BehaviorListType.subclass(*args_, **kwargs_)
        else:
            return BehaviorListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Behavior(self): return self.Behavior
    def set_Behavior(self, Behavior): self.Behavior = Behavior
    def add_Behavior(self, value): self.Behavior.append(value)
    def insert_Behavior(self, index, value): self.Behavior[index] = value
    def hasContent_(self):
        if (
            self.Behavior
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Behavior_ in self.Behavior:
            Behavior_.export(write, level, 'maecBundle:', name_='Behavior', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Behavior':
            obj_ = BehaviorType.factory()
            obj_.build(child_)
            self.Behavior.append(obj_)
# end class BehaviorListType

class ActionListType(GeneratedsSuper):
    """The ActionListType captures a list of Actions."""
    subclass = None
    superclass = None
    def __init__(self, Action=None):
        if Action is None:
            self.Action = []
        else:
            self.Action = Action
    def factory(*args_, **kwargs_):
        if ActionListType.subclass:
            return ActionListType.subclass(*args_, **kwargs_)
        else:
            return ActionListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action(self): return self.Action
    def set_Action(self, Action): self.Action = Action
    def add_Action(self, value): self.Action.append(value)
    def insert_Action(self, index, value): self.Action[index] = value
    def hasContent_(self):
        if (
            self.Action
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ActionListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ActionListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ActionListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ActionListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Action_ in self.Action:
            Action_.export(write, level, 'maecBundle:', name_='Action', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action':
            obj_ = MalwareActionType.factory()
            obj_.build(child_)
            self.add_Action(obj_)
# end class ActionListType

class ObjectListType(GeneratedsSuper):
    """The ObjectListType captures a list of CybOX Objects."""
    subclass = None
    superclass = None
    def __init__(self, Object=None):
        if Object is None:
            self.Object = []
        else:
            self.Object = Object
    def factory(*args_, **kwargs_):
        if ObjectListType.subclass:
            return ObjectListType.subclass(*args_, **kwargs_)
        else:
            return ObjectListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Object(self): return self.Object
    def set_Object(self, Object): self.Object = Object
    def add_Object(self, value): self.Object.append(value)
    def insert_Object(self, index, value): self.Object[index] = value
    def hasContent_(self):
        if (
            self.Object
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ObjectListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ObjectListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ObjectListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ObjectListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Object_ in self.Object:
            Object_.export(write, level, 'maecBundle:', name_='Object', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Object':
            obj_ = cybox_core.ObjectType.factory()
            obj_.build(child_)
            self.add_Object(obj_)
# end class ObjectListType

class BehaviorReferenceType(GeneratedsSuper):
    """The BehaviorReferenceType serves as a method for referencing
    existing behaviors contained in the Bundle.The behavior_idref
    field specifies the id of the Behavior being referenced; this
    Behavior must be present in the current Bundle."""
    subclass = None
    superclass = None
    def __init__(self, behavior_idref=None):
        self.behavior_idref = _cast(None, behavior_idref)
        pass
    def factory(*args_, **kwargs_):
        if BehaviorReferenceType.subclass:
            return BehaviorReferenceType.subclass(*args_, **kwargs_)
        else:
            return BehaviorReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_behavior_idref(self): return self.behavior_idref
    def set_behavior_idref(self, behavior_idref): self.behavior_idref = behavior_idref
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorReferenceType'):
        if self.behavior_idref is not None and 'behavior_idref' not in already_processed:
            already_processed.add('behavior_idref')
            write(' behavior_idref=%s' % (quote_attrib(self.behavior_idref), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorReferenceType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('behavior_idref', node)
        if value is not None and 'behavior_idref' not in already_processed:
            already_processed.add('behavior_idref')
            self.behavior_idref = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class BehaviorReferenceType

class ObjectReferenceType(GeneratedsSuper):
    """The ObjectReferenceType serves as a method for linking to CybOX
    Objects embedded in the MAEC Bundle.The object_idref field
    specifies the id of a CybOX Object being referenced in the
    current MAEC Bundle."""
    subclass = None
    superclass = None
    def __init__(self, object_idref=None):
        self.object_idref = _cast(None, object_idref)
        pass
    def factory(*args_, **kwargs_):
        if ObjectReferenceType.subclass:
            return ObjectReferenceType.subclass(*args_, **kwargs_)
        else:
            return ObjectReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_object_idref(self): return self.object_idref
    def set_object_idref(self, object_idref): self.object_idref = object_idref
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ObjectReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ObjectReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ObjectReferenceType'):
        if self.object_idref is not None and 'object_idref' not in already_processed:
            already_processed.add('object_idref')
            write(' object_idref=%s' % (quote_attrib(self.object_idref), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ObjectReferenceType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('object_idref', node)
        if value is not None and 'object_idref' not in already_processed:
            already_processed.add('object_idref')
            self.object_idref = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class ObjectReferenceType

class BehavioralActionEquivalenceReferenceType(GeneratedsSuper):
    """The BehavioralActionEquivalenceReferenceType defines an Action
    Equivalence reference that can be used as part of a Behavior.
    Since the Action Equivalency equates two or more actions to a
    single one, this can be thought of as specifying one of the
    aforementioned Actions as part of the composition of the
    Behavior.The action_equivalence_idref field specifies the ID of
    an Action Equivalence contained in the same MAEC document as the
    Behavior that utilizes it.The behavioral_ordering field defines
    the ordering of the Action Equivalency with respect to the other
    actions that make up the behavior. So an action with a
    behavioral_ordering of "1" would come before an action with a
    behavioral_ordering of "2", etc."""
    subclass = None
    superclass = None
    def __init__(self, action_equivalence_idref=None, behavioral_ordering=None):
        self.action_equivalence_idref = _cast(None, action_equivalence_idref)
        self.behavioral_ordering = _cast(int, behavioral_ordering)
        pass
    def factory(*args_, **kwargs_):
        if BehavioralActionEquivalenceReferenceType.subclass:
            return BehavioralActionEquivalenceReferenceType.subclass(*args_, **kwargs_)
        else:
            return BehavioralActionEquivalenceReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_action_equivalence_idref(self): return self.action_equivalence_idref
    def set_action_equivalence_idref(self, action_equivalence_idref): self.action_equivalence_idref = action_equivalence_idref
    def get_behavioral_ordering(self): return self.behavioral_ordering
    def set_behavioral_ordering(self, behavioral_ordering): self.behavioral_ordering = behavioral_ordering
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehavioralActionEquivalenceReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehavioralActionEquivalenceReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehavioralActionEquivalenceReferenceType'):
        if self.action_equivalence_idref is not None and 'action_equivalence_idref' not in already_processed:
            already_processed.add('action_equivalence_idref')
            write(' action_equivalence_idref=%s' % (quote_attrib(self.action_equivalence_idref), ))
        if self.behavioral_ordering is not None and 'behavioral_ordering' not in already_processed:
            already_processed.add('behavioral_ordering')
            write(' behavioral_ordering="%s"' % self.gds_format_integer(self.behavioral_ordering, input_name='behavioral_ordering'))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehavioralActionEquivalenceReferenceType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('action_equivalence_idref', node)
        if value is not None and 'action_equivalence_idref' not in already_processed:
            already_processed.add('action_equivalence_idref')
            self.action_equivalence_idref = value
        value = find_attr_value_('behavioral_ordering', node)
        if value is not None and 'behavioral_ordering' not in already_processed:
            already_processed.add('behavioral_ordering')
            try:
                self.behavioral_ordering = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
            if self.behavioral_ordering <= 0:
                raise_parse_error(node, 'Invalid PositiveInteger')
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class BehavioralActionEquivalenceReferenceType

class BehaviorReferenceListType(GeneratedsSuper):
    """The BehaviorReferenceListType captures a list of Behavior
    References."""
    subclass = None
    superclass = None
    def __init__(self, Behavior_Reference=None):
        if Behavior_Reference is None:
            self.Behavior_Reference = []
        else:
            self.Behavior_Reference = Behavior_Reference
    def factory(*args_, **kwargs_):
        if BehaviorReferenceListType.subclass:
            return BehaviorReferenceListType.subclass(*args_, **kwargs_)
        else:
            return BehaviorReferenceListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Behavior_Reference(self): return self.Behavior_Reference
    def set_Behavior_Reference(self, Behavior_Reference): self.Behavior_Reference = Behavior_Reference
    def add_Behavior_Reference(self, value): self.Behavior_Reference.append(value)
    def insert_Behavior_Reference(self, index, value): self.Behavior_Reference[index] = value
    def hasContent_(self):
        if (
            self.Behavior_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorReferenceListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorReferenceListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorReferenceListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorReferenceListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Behavior_Reference_ in self.Behavior_Reference:
            Behavior_Reference_.export(write, level, 'maecBundle:', name_='Behavior_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Behavior_Reference':
            obj_ = BehaviorReferenceType.factory()
            obj_.build(child_)
            self.Behavior_Reference.append(obj_)
# end class BehaviorReferenceListType

class ActionReferenceListType(GeneratedsSuper):
    """The ActionReferenceListType captures a list of Action References."""
    subclass = None
    superclass = None
    def __init__(self, Action_Reference=None):
        if Action_Reference is None:
            self.Action_Reference = []
        else:
            self.Action_Reference = Action_Reference
    def factory(*args_, **kwargs_):
        if ActionReferenceListType.subclass:
            return ActionReferenceListType.subclass(*args_, **kwargs_)
        else:
            return ActionReferenceListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action_Reference(self): return self.Action_Reference
    def set_Action_Reference(self, Action_Reference): self.Action_Reference = Action_Reference
    def add_Action_Reference(self, value): self.Action_Reference.append(value)
    def insert_Action_Reference(self, index, value): self.Action_Reference[index] = value
    def hasContent_(self):
        if (
            self.Action_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ActionReferenceListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ActionReferenceListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ActionReferenceListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ActionReferenceListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Action_Reference_ in self.Action_Reference:
            Action_Reference_.export(write, level, 'maecBundle:', name_='Action_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action_Reference':
            obj_ = cybox_core.ActionReferenceType.factory()
            obj_.build(child_)
            self.add_Action_Reference(obj_)
# end class ActionReferenceListType

class ObjectReferenceListType(GeneratedsSuper):
    """The ObjectReferenceListType captures a list of references to CybOX
    Objects."""
    subclass = None
    superclass = None
    def __init__(self, Object_Reference=None):
        if Object_Reference is None:
            self.Object_Reference = []
        else:
            self.Object_Reference = Object_Reference
    def factory(*args_, **kwargs_):
        if ObjectReferenceListType.subclass:
            return ObjectReferenceListType.subclass(*args_, **kwargs_)
        else:
            return ObjectReferenceListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Object_Reference(self): return self.Object_Reference
    def set_Object_Reference(self, Object_Reference): self.Object_Reference = Object_Reference
    def add_Object_Reference(self, value): self.Object_Reference.append(value)
    def insert_Object_Reference(self, index, value): self.Object_Reference[index] = value
    def hasContent_(self):
        if (
            self.Object_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ObjectReferenceListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ObjectReferenceListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ObjectReferenceListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ObjectReferenceListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Object_Reference_ in self.Object_Reference:
            Object_Reference_.export(write, level, 'maecBundle:', name_='Object_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Object_Reference':
            obj_ = ObjectReferenceType.factory()
            obj_.build(child_)
            self.Object_Reference.append(obj_)
# end class ObjectReferenceListType

class CandidateIndicatorType(GeneratedsSuper):
    """The CandidateIndicatorType provides a way of defining a MAEC entity-
    based Candidate Indicator, which specifies the particular
    components that may signify the presence of the malware instance
    on a host system or network.The id field specifies a unique ID
    for this Candidate Indicator. The ID must follow the pattern
    defined in the CandidateIndicatorIDPattern simple type.The
    creation_datetime field specifies the date/time that the
    Candidate Indicator was created.The lastupdate_datetime field
    specifies the last date/time that the Candidate Indicator was
    updated.The version field specifies the version of the Candidate
    Indicator."""
    subclass = None
    superclass = None
    def __init__(self, version=None, creation_datetime=None, id=None, lastupdate_datetime=None, Importance=None, Numeric_Importance=None, Author=None, Description=None, Malware_Entity=None, Composition=None):
        self.version = _cast(None, version)
        self.creation_datetime = _cast(None, creation_datetime)
        self.id = _cast(None, id)
        self.lastupdate_datetime = _cast(None, lastupdate_datetime)
        self.Importance = Importance
        self.Numeric_Importance = Numeric_Importance
        self.Author = Author
        self.Description = Description
        self.Malware_Entity = Malware_Entity
        self.Composition = Composition
    def factory(*args_, **kwargs_):
        if CandidateIndicatorType.subclass:
            return CandidateIndicatorType.subclass(*args_, **kwargs_)
        else:
            return CandidateIndicatorType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Importance(self): return self.Importance
    def set_Importance(self, Importance): self.Importance = Importance
    def get_Numeric_Importance(self): return self.Numeric_Importance
    def set_Numeric_Importance(self, Numeric_Importance): self.Numeric_Importance = Numeric_Importance
    def get_Author(self): return self.Author
    def set_Author(self, Author): self.Author = Author
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_Malware_Entity(self): return self.Malware_Entity
    def set_Malware_Entity(self, Malware_Entity): self.Malware_Entity = Malware_Entity
    def get_Composition(self): return self.Composition
    def set_Composition(self, Composition): self.Composition = Composition
    def get_version(self): return self.version
    def set_version(self, version): self.version = version
    def get_creation_datetime(self): return self.creation_datetime
    def set_creation_datetime(self, creation_datetime): self.creation_datetime = creation_datetime
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def get_lastupdate_datetime(self): return self.lastupdate_datetime
    def set_lastupdate_datetime(self, lastupdate_datetime): self.lastupdate_datetime = lastupdate_datetime
    def hasContent_(self):
        if (
            self.Importance is not None or
            self.Numeric_Importance is not None or
            self.Author is not None or
            self.Description is not None or
            self.Malware_Entity is not None or
            self.Composition is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CandidateIndicatorType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CandidateIndicatorType'):
        if self.version is not None and 'version' not in already_processed:
            already_processed.add('version')
            write(' version=%s' % (quote_attrib(self.version)))
        if self.creation_datetime is not None and 'creation_datetime' not in already_processed:
            already_processed.add('creation_datetime')
            write(' creation_datetime="%s"' % self.gds_format_datetime(self.creation_datetime, input_name='creation_datetime'))
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
        if self.lastupdate_datetime is not None and 'lastupdate_datetime' not in already_processed:
            already_processed.add('lastupdate_datetime')
            write(' lastupdate_datetime="%s"' % self.gds_format_datetime(self.lastupdate_datetime, input_name='lastupdate_datetime'))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Importance is not None:
            self.Importance.export(write, level, 'maecBundle:', name_='Importance', pretty_print=pretty_print)
        if self.Numeric_Importance is not None:
            showIndent(write, level, pretty_print)
            write('<%sNumeric_Importance>%s</%sNumeric_Importance>%s' % ('maecBundle:', self.gds_format_integer(self.Numeric_Importance, input_name='Numeric_Importance'), 'maecBundle:', eol_))
        if self.Author is not None:
            showIndent(write, level, pretty_print)
            write('<%sAuthor>%s</%sAuthor>%s' % ('maecBundle:', quote_xml(self.Author), 'maecBundle:', eol_))
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
        if self.Malware_Entity is not None:
            self.Malware_Entity.export(write, level, 'maecBundle:', name_='Malware_Entity', pretty_print=pretty_print)
        if self.Composition is not None:
            self.Composition.export(write, level, 'maecBundle:', name_='Composition', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('version', node)
        if value is not None and 'version' not in already_processed:
            already_processed.add('version')
            self.version = value
        value = find_attr_value_('creation_datetime', node)
        if value is not None and 'creation_datetime' not in already_processed:
            already_processed.add('creation_datetime')
            try:
                self.creation_datetime = value
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (creation_datetime): %s' % exp)
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.add('id')
            self.id = value
        value = find_attr_value_('lastupdate_datetime', node)
        if value is not None and 'lastupdate_datetime' not in already_processed:
            already_processed.add('lastupdate_datetime')
            try:
                self.lastupdate_datetime = value
            except ValueError, exp:
                raise ValueError('Bad date-time attribute (lastupdate_datetime): %s' % exp)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Importance':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Importance(obj_)
        elif nodeName_ == 'Numeric_Importance':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            if ival_ <= 0:
                raise_parse_error(child_, 'requires positiveInteger')
            ival_ = self.gds_validate_integer(ival_, node, 'Numeric_Importance')
            self.Numeric_Importance = ival_
        elif nodeName_ == 'Author':
            Author_ = child_.text
            Author_ = self.gds_validate_string(Author_, node, 'Author')
            self.Author = Author_
        elif nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
        elif nodeName_ == 'Malware_Entity':
            obj_ = MalwareEntityType.factory()
            obj_.build(child_)
            self.set_Malware_Entity(obj_)
        elif nodeName_ == 'Composition':
            obj_ = CandidateIndicatorCompositionType.factory()
            obj_.build(child_)
            self.set_Composition(obj_)
# end class CandidateIndicatorType

class CandidateIndicatorListType(GeneratedsSuper):
    """The CandidateIndicatorListType captures a list of Candidate
    Indicators."""
    subclass = None
    superclass = None
    def __init__(self, Candidate_Indicator=None):
        if Candidate_Indicator is None:
            self.Candidate_Indicator = []
        else:
            self.Candidate_Indicator = Candidate_Indicator
    def factory(*args_, **kwargs_):
        if CandidateIndicatorListType.subclass:
            return CandidateIndicatorListType.subclass(*args_, **kwargs_)
        else:
            return CandidateIndicatorListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Candidate_Indicator(self): return self.Candidate_Indicator
    def set_Candidate_Indicator(self, Candidate_Indicator): self.Candidate_Indicator = Candidate_Indicator
    def add_Candidate_Indicator(self, value): self.Candidate_Indicator.append(value)
    def insert_Candidate_Indicator(self, index, value): self.Candidate_Indicator[index] = value
    def hasContent_(self):
        if (
            self.Candidate_Indicator
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CandidateIndicatorListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CandidateIndicatorListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Candidate_Indicator_ in self.Candidate_Indicator:
            Candidate_Indicator_.export(write, level, 'maecBundle:', name_='Candidate_Indicator', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Candidate_Indicator':
            obj_ = CandidateIndicatorType.factory()
            obj_.build(child_)
            self.Candidate_Indicator.append(obj_)
# end class CandidateIndicatorListType

class MalwareEntityType(GeneratedsSuper):
    """The MalwareEntityType provides a mechanism for characterizing the
    particular entity that an indicator or signature is written
    against, whether it is a particular malware instance, family,
    etc."""
    subclass = None
    superclass = None
    def __init__(self, Type=None, Name=None, Description=None):
        self.Type = Type
        self.Name = Name
        self.Description = Description
    def factory(*args_, **kwargs_):
        if MalwareEntityType.subclass:
            return MalwareEntityType.subclass(*args_, **kwargs_)
        else:
            return MalwareEntityType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Type(self): return self.Type
    def set_Type(self, Type): self.Type = Type
    def get_Name(self): return self.Name
    def set_Name(self, Name): self.Name = Name
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def hasContent_(self):
        if (
            self.Type is not None or
            self.Name is not None or
            self.Description is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='MalwareEntityType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareEntityType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='MalwareEntityType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='MalwareEntityType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Type is not None:
            self.Type.export(write, level, 'maecBundle:', name_='Type', pretty_print=pretty_print)
        if self.Name is not None:
            showIndent(write, level, pretty_print)
            write('<%sName>%s</%sName>%s' % ('maecBundle:', quote_xml(self.Name), 'maecBundle:', eol_))
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
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
        elif nodeName_ == 'Name':
            Name_ = child_.text
            Name_ = self.gds_validate_string(Name_, node, 'Name')
            self.Name = Name_
        elif nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
# end class MalwareEntityType

class CollectionsType(GeneratedsSuper):
    """The CollectionsType captures the various types of MAEC entity
    collections."""
    subclass = None
    superclass = None
    def __init__(self, Behavior_Collections=None, Action_Collections=None, Object_Collections=None, Candidate_Indicator_Collections=None):
        self.Behavior_Collections = Behavior_Collections
        self.Action_Collections = Action_Collections
        self.Object_Collections = Object_Collections
        self.Candidate_Indicator_Collections = Candidate_Indicator_Collections
    def factory(*args_, **kwargs_):
        if CollectionsType.subclass:
            return CollectionsType.subclass(*args_, **kwargs_)
        else:
            return CollectionsType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Behavior_Collections(self): return self.Behavior_Collections
    def set_Behavior_Collections(self, Behavior_Collections): self.Behavior_Collections = Behavior_Collections
    def get_Action_Collections(self): return self.Action_Collections
    def set_Action_Collections(self, Action_Collections): self.Action_Collections = Action_Collections
    def get_Object_Collections(self): return self.Object_Collections
    def set_Object_Collections(self, Object_Collections): self.Object_Collections = Object_Collections
    def get_Candidate_Indicator_Collections(self): return self.Candidate_Indicator_Collections
    def set_Candidate_Indicator_Collections(self, Candidate_Indicator_Collections): self.Candidate_Indicator_Collections = Candidate_Indicator_Collections
    def hasContent_(self):
        if (
            self.Behavior_Collections is not None or
            self.Action_Collections is not None or
            self.Object_Collections is not None or
            self.Candidate_Indicator_Collections is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CollectionsType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CollectionsType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CollectionsType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CollectionsType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Behavior_Collections is not None:
            self.Behavior_Collections.export(write, level, 'maecBundle:', name_='Behavior_Collections', pretty_print=pretty_print)
        if self.Action_Collections is not None:
            self.Action_Collections.export(write, level, 'maecBundle:', name_='Action_Collections', pretty_print=pretty_print)
        if self.Object_Collections is not None:
            self.Object_Collections.export(write, level, 'maecBundle:', name_='Object_Collections', pretty_print=pretty_print)
        if self.Candidate_Indicator_Collections is not None:
            self.Candidate_Indicator_Collections.export(write, level, 'maecBundle:', name_='Candidate_Indicator_Collections', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Behavior_Collections':
            obj_ = BehaviorCollectionListType.factory()
            obj_.build(child_)
            self.set_Behavior_Collections(obj_)
        elif nodeName_ == 'Action_Collections':
            obj_ = ActionCollectionListType.factory()
            obj_.build(child_)
            self.set_Action_Collections(obj_)
        elif nodeName_ == 'Object_Collections':
            obj_ = ObjectCollectionListType.factory()
            obj_.build(child_)
            self.set_Object_Collections(obj_)
        elif nodeName_ == 'Candidate_Indicator_Collections':
            obj_ = CandidateIndicatorCollectionListType.factory()
            obj_.build(child_)
            self.set_Candidate_Indicator_Collections(obj_)
# end class CollectionsType

class BundleReferenceType(GeneratedsSuper):
    """The BundleReferenceType serves as a method for linking to Bundles
    embedded in other locations.The bundle_idref field references
    the ID of a Bundle contained inside the current MAEC document."""
    subclass = None
    superclass = None
    def __init__(self, bundle_idref=None):
        self.bundle_idref = _cast(None, bundle_idref)
        pass
    def factory(*args_, **kwargs_):
        if BundleReferenceType.subclass:
            return BundleReferenceType.subclass(*args_, **kwargs_)
        else:
            return BundleReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_bundle_idref(self): return self.bundle_idref
    def set_bundle_idref(self, bundle_idref): self.bundle_idref = bundle_idref
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BundleReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BundleReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BundleReferenceType'):
        if self.bundle_idref is not None and 'bundle_idref' not in already_processed:
            already_processed.add('bundle_idref')
            write(' bundle_idref=%s' % (quote_attrib(self.bundle_idref), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BundleReferenceType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('bundle_idref', node)
        if value is not None and 'bundle_idref' not in already_processed:
            already_processed.add('bundle_idref')
            self.bundle_idref = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class BundleReferenceType

class ProcessTreeType(GeneratedsSuper):
    """The ProcessTreeType captures the process tree for the malware
    instance, including the parent process and processes spawned by
    it, along with any Actions initiated by each."""
    subclass = None
    superclass = None
    def __init__(self, Root_Process=None):
        self.Root_Process = Root_Process
    def factory(*args_, **kwargs_):
        if ProcessTreeType.subclass:
            return ProcessTreeType.subclass(*args_, **kwargs_)
        else:
            return ProcessTreeType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Root_Process(self): return self.Root_Process
    def set_Root_Process(self, Root_Process): self.Root_Process = Root_Process
    def hasContent_(self):
        if (
            self.Root_Process is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ProcessTreeType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ProcessTreeType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ProcessTreeType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ProcessTreeType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Root_Process is not None:
            self.Root_Process.export(write, level, 'maecBundle:', name_='Root_Process', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Root_Process':
            obj_ = ProcessTreeNodeType.factory()
            obj_.build(child_)
            self.set_Root_Process(obj_)
# end class ProcessTreeType

class CandidateIndicatorCompositionType(GeneratedsSuper):
    """The CandidateIndicatorCompositionType captures the composition of a
    Candidate Indicator, via references to any corresponding MAEC
    entities contained in the Bundle.The operator field specifies
    the Boolean operator for this level of the Candidate Indicator's
    composition."""
    subclass = None
    superclass = None
    def __init__(self, operator=None, Behavior_Reference=None, Action_Reference=None, Object_Reference=None, Sub_Composition=None):
        self.operator = _cast(None, operator)
        if Behavior_Reference is None:
            self.Behavior_Reference = []
        else:
            self.Behavior_Reference = Behavior_Reference
        if Action_Reference is None:
            self.Action_Reference = []
        else:
            self.Action_Reference = Action_Reference
        if Object_Reference is None:
            self.Object_Reference = []
        else:
            self.Object_Reference = Object_Reference
        if Sub_Composition is None:
            self.Sub_Composition = []
        else:
            self.Sub_Composition = Sub_Composition
    def factory(*args_, **kwargs_):
        if CandidateIndicatorCompositionType.subclass:
            return CandidateIndicatorCompositionType.subclass(*args_, **kwargs_)
        else:
            return CandidateIndicatorCompositionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Behavior_Reference(self): return self.Behavior_Reference
    def set_Behavior_Reference(self, Behavior_Reference): self.Behavior_Reference = Behavior_Reference
    def add_Behavior_Reference(self, value): self.Behavior_Reference.append(value)
    def insert_Behavior_Reference(self, index, value): self.Behavior_Reference[index] = value
    def get_Action_Reference(self): return self.Action_Reference
    def set_Action_Reference(self, Action_Reference): self.Action_Reference = Action_Reference
    def add_Action_Reference(self, value): self.Action_Reference.append(value)
    def insert_Action_Reference(self, index, value): self.Action_Reference[index] = value
    def get_Object_Reference(self): return self.Object_Reference
    def set_Object_Reference(self, Object_Reference): self.Object_Reference = Object_Reference
    def add_Object_Reference(self, value): self.Object_Reference.append(value)
    def insert_Object_Reference(self, index, value): self.Object_Reference[index] = value
    def get_Sub_Composition(self): return self.Sub_Composition
    def set_Sub_Composition(self, Sub_Composition): self.Sub_Composition = Sub_Composition
    def add_Sub_Composition(self, value): self.Sub_Composition.append(value)
    def insert_Sub_Composition(self, index, value): self.Sub_Composition[index] = value
    def get_operator(self): return self.operator
    def set_operator(self, operator): self.operator = operator
    def hasContent_(self):
        if (
            self.Behavior_Reference or
            self.Action_Reference or
            self.Object_Reference or
            self.Sub_Composition
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorCompositionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CandidateIndicatorCompositionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CandidateIndicatorCompositionType'):
        if self.operator is not None and 'operator' not in already_processed:
            already_processed.add('operator')
            write(' operator=%s' % (quote_attrib(self.operator), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorCompositionType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Behavior_Reference_ in self.Behavior_Reference:
            Behavior_Reference_.export(write, level, 'maecBundle:', name_='Behavior_Reference', pretty_print=pretty_print)
        for Action_Reference_ in self.Action_Reference:
            Action_Reference_.export(write, level, 'maecBundle:', name_='Action_Reference', pretty_print=pretty_print)
        for Object_Reference_ in self.Object_Reference:
            Object_Reference_.export(write, level, 'maecBundle:', name_='Object_Reference', pretty_print=pretty_print)
        for Sub_Composition_ in self.Sub_Composition:
            Sub_Composition_.export(write, level, 'maecBundle:', name_='Sub_Composition', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('operator', node)
        if value is not None and 'operator' not in already_processed:
            already_processed.add('operator')
            self.operator = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Behavior_Reference':
            obj_ = BehaviorReferenceType.factory()
            obj_.build(child_)
            self.Behavior_Reference.append(obj_)
        elif nodeName_ == 'Action_Reference':
            obj_ = BehavioralActionReferenceType.factory()
            obj_.build(child_)
            self.set_Action_Reference(obj_)
        elif nodeName_ == 'Object_Reference':
            obj_ = ObjectReferenceType.factory()
            obj_.build(child_)
            self.Object_Reference.append(obj_)
        elif nodeName_ == 'Sub_Composition':
            obj_ = CandidateIndicatorCompositionType.factory()
            obj_.build(child_)
            self.Sub_Composition.append(obj_)
# end class CandidateIndicatorCompositionType

class CandidateIndicatorCollectionType(BaseCollectionType):
    """The CandidateIndicatorCollectionType provides a mechanism for
    characterizing collections of Candidate Indicators.The id field
    specifies a unique ID for this Candidate Indicator Collection.
    The ID must follow the pattern defined in the
    CandidateIndicatorCollIDPattern simple type."""
    subclass = None
    superclass = BaseCollectionType
    def __init__(self, name=None, Affinity_Type=None, Affinity_Degree=None, Description=None, id=None, Candidate_Indicator_List=None):
        super(CandidateIndicatorCollectionType, self).__init__(name, Affinity_Type, Affinity_Degree, Description, )
        self.id = _cast(None, id)
        self.Candidate_Indicator_List = Candidate_Indicator_List
    def factory(*args_, **kwargs_):
        if CandidateIndicatorCollectionType.subclass:
            return CandidateIndicatorCollectionType.subclass(*args_, **kwargs_)
        else:
            return CandidateIndicatorCollectionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Candidate_Indicator_List(self): return self.Candidate_Indicator_List
    def set_Candidate_Indicator_List(self, Candidate_Indicator_List): self.Candidate_Indicator_List = Candidate_Indicator_List
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Candidate_Indicator_List is not None or
            super(CandidateIndicatorCollectionType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorCollectionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CandidateIndicatorCollectionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CandidateIndicatorCollectionType'):
        super(CandidateIndicatorCollectionType, self).exportAttributes(write, level, already_processed, namespace_, name_='CandidateIndicatorCollectionType')
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorCollectionType', fromsubclass_=False, pretty_print=True):
        super(CandidateIndicatorCollectionType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Candidate_Indicator_List is not None:
            self.Candidate_Indicator_List.export(write, level, 'maecBundle:', name_='Candidate_Indicator_List', pretty_print=pretty_print)
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
        super(CandidateIndicatorCollectionType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Candidate_Indicator_List':
            obj_ = CandidateIndicatorListType.factory()
            obj_.build(child_)
            self.set_Candidate_Indicator_List(obj_)
        super(CandidateIndicatorCollectionType, self).buildChildren(child_, node, nodeName_, True)
# end class CandidateIndicatorCollectionType

class CandidateIndicatorCollectionListType(GeneratedsSuper):
    """The CandidateIndicatorCollectionListType captures a list of
    Candidate Indicators."""
    subclass = None
    superclass = None
    def __init__(self, Candidate_Indicator_Collection=None):
        if Candidate_Indicator_Collection is None:
            self.Candidate_Indicator_Collection = []
        else:
            self.Candidate_Indicator_Collection = Candidate_Indicator_Collection
    def factory(*args_, **kwargs_):
        if CandidateIndicatorCollectionListType.subclass:
            return CandidateIndicatorCollectionListType.subclass(*args_, **kwargs_)
        else:
            return CandidateIndicatorCollectionListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Candidate_Indicator_Collection(self): return self.Candidate_Indicator_Collection
    def set_Candidate_Indicator_Collection(self, Candidate_Indicator_Collection): self.Candidate_Indicator_Collection = Candidate_Indicator_Collection
    def add_Candidate_Indicator_Collection(self, value): self.Candidate_Indicator_Collection.append(value)
    def insert_Candidate_Indicator_Collection(self, index, value): self.Candidate_Indicator_Collection[index] = value
    def hasContent_(self):
        if (
            self.Candidate_Indicator_Collection
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorCollectionListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CandidateIndicatorCollectionListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CandidateIndicatorCollectionListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CandidateIndicatorCollectionListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Candidate_Indicator_Collection_ in self.Candidate_Indicator_Collection:
            Candidate_Indicator_Collection_.export(write, level, 'maecBundle:', name_='Candidate_Indicator_Collection', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Candidate_Indicator_Collection':
            obj_ = CandidateIndicatorCollectionType.factory()
            obj_.build(child_)
            self.Candidate_Indicator_Collection.append(obj_)
# end class CandidateIndicatorCollectionListType

class BehaviorCollectionListType(GeneratedsSuper):
    """The BehaviorCollectionListType captures a list of Behaviors
    Collections."""
    subclass = None
    superclass = None
    def __init__(self, Behavior_Collection=None):
        if Behavior_Collection is None:
            self.Behavior_Collection = []
        else:
            self.Behavior_Collection = Behavior_Collection
    def factory(*args_, **kwargs_):
        if BehaviorCollectionListType.subclass:
            return BehaviorCollectionListType.subclass(*args_, **kwargs_)
        else:
            return BehaviorCollectionListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Behavior_Collection(self): return self.Behavior_Collection
    def set_Behavior_Collection(self, Behavior_Collection): self.Behavior_Collection = Behavior_Collection
    def add_Behavior_Collection(self, value): self.Behavior_Collection.append(value)
    def insert_Behavior_Collection(self, index, value): self.Behavior_Collection[index] = value
    def hasContent_(self):
        if (
            self.Behavior_Collection
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorCollectionListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorCollectionListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorCollectionListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorCollectionListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Behavior_Collection_ in self.Behavior_Collection:
            Behavior_Collection_.export(write, level, 'maecBundle:', name_='Behavior_Collection', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Behavior_Collection':
            obj_ = BehaviorCollectionType.factory()
            obj_.build(child_)
            self.Behavior_Collection.append(obj_)
# end class BehaviorCollectionListType

class ActionCollectionListType(GeneratedsSuper):
    """The ActionCollectionListType captures a list of Actions Collections."""
    subclass = None
    superclass = None
    def __init__(self, Action_Collection=None):
        if Action_Collection is None:
            self.Action_Collection = []
        else:
            self.Action_Collection = Action_Collection
    def factory(*args_, **kwargs_):
        if ActionCollectionListType.subclass:
            return ActionCollectionListType.subclass(*args_, **kwargs_)
        else:
            return ActionCollectionListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action_Collection(self): return self.Action_Collection
    def set_Action_Collection(self, Action_Collection): self.Action_Collection = Action_Collection
    def add_Action_Collection(self, value): self.Action_Collection.append(value)
    def insert_Action_Collection(self, index, value): self.Action_Collection[index] = value
    def hasContent_(self):
        if (
            self.Action_Collection
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ActionCollectionListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ActionCollectionListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ActionCollectionListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ActionCollectionListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Action_Collection_ in self.Action_Collection:
            Action_Collection_.export(write, level, 'maecBundle:', name_='Action_Collection', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action_Collection':
            obj_ = ActionCollectionType.factory()
            obj_.build(child_)
            self.Action_Collection.append(obj_)
# end class ActionCollectionListType

class ObjectCollectionListType(GeneratedsSuper):
    """The ObjectCollectionListType captures a list of Object Collections."""
    subclass = None
    superclass = None
    def __init__(self, Object_Collection=None):
        if Object_Collection is None:
            self.Object_Collection = []
        else:
            self.Object_Collection = Object_Collection
    def factory(*args_, **kwargs_):
        if ObjectCollectionListType.subclass:
            return ObjectCollectionListType.subclass(*args_, **kwargs_)
        else:
            return ObjectCollectionListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Object_Collection(self): return self.Object_Collection
    def set_Object_Collection(self, Object_Collection): self.Object_Collection = Object_Collection
    def add_Object_Collection(self, value): self.Object_Collection.append(value)
    def insert_Object_Collection(self, index, value): self.Object_Collection[index] = value
    def hasContent_(self):
        if (
            self.Object_Collection
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ObjectCollectionListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ObjectCollectionListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ObjectCollectionListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ObjectCollectionListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Object_Collection_ in self.Object_Collection:
            Object_Collection_.export(write, level, 'maecBundle:', name_='Object_Collection', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Object_Collection':
            obj_ = ObjectCollectionType.factory()
            obj_.build(child_)
            self.Object_Collection.append(obj_)
# end class ObjectCollectionListType

class AVClassificationType(cybox_common.ToolInformationType):
    """The AVClassificationType captures information on AV scanner
    classifications for the malware instance object captured in the
    Bundle or Package."""
    subclass = None
    superclass = cybox_common.ToolInformationType
    def __init__(self, idref=None, id=None, Name=None, Type=None, Description=None, References=None, Vendor=None, Version=None, Service_Pack=None, Tool_Specific_Data=None, Tool_Hashes=None, Tool_Configuration=None, Execution_Environment=None, Errors=None, Metadata=None, Engine_Version=None, Definition_Version=None, Classification_Name=None):
        super(AVClassificationType, self).__init__(idref, id, Name, Type, Description, References, Vendor, Version, Service_Pack, Tool_Specific_Data, Tool_Hashes, Tool_Configuration, Execution_Environment, Errors, Metadata, )
        self.Engine_Version = Engine_Version
        self.Definition_Version = Definition_Version
        self.Classification_Name = Classification_Name
    def factory(*args_, **kwargs_):
        if AVClassificationType.subclass:
            return AVClassificationType.subclass(*args_, **kwargs_)
        else:
            return AVClassificationType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Engine_Version(self): return self.Engine_Version
    def set_Engine_Version(self, Engine_Version): self.Engine_Version = Engine_Version
    def get_Definition_Version(self): return self.Definition_Version
    def set_Definition_Version(self, Definition_Version): self.Definition_Version = Definition_Version
    def get_Classification_Name(self): return self.Classification_Name
    def set_Classification_Name(self, Classification_Name): self.Classification_Name = Classification_Name
    def hasContent_(self):
        if (
            self.Engine_Version is not None or
            self.Definition_Version is not None or
            self.Classification_Name is not None or
            super(AVClassificationType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='AVClassificationType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='AVClassificationType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='AVClassificationType'):
        super(AVClassificationType, self).exportAttributes(write, level, already_processed, namespace_, name_='AVClassificationType')
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='AVClassificationType', fromsubclass_=False, pretty_print=True):
        super(AVClassificationType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Engine_Version is not None:
            showIndent(write, level, pretty_print)
            write('<%sEngine_Version>%s</%sEngine_Version>%s' % ('maecBundle:', quote_xml(self.Engine_Version), 'maecBundle:', eol_))
        if self.Definition_Version is not None:
            showIndent(write, level, pretty_print)
            write('<%sDefinition_Version>%s</%sDefinition_Version>%s' % ('maecBundle:', quote_xml(self.Definition_Version), 'maecBundle:', eol_))
        if self.Classification_Name is not None:
            showIndent(write, level, pretty_print)
            write('<%sClassification_Name>%s</%sClassification_Name>%s' % ('maecBundle:', quote_xml(self.Classification_Name), 'maecBundle:', eol_))
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        super(AVClassificationType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Engine_Version':
            Engine_Version_ = child_.text
            Engine_Version_ = self.gds_validate_string(Engine_Version_, node, 'Engine_Version')
            self.Engine_Version = Engine_Version_
        elif nodeName_ == 'Definition_Version':
            Definition_Version_ = child_.text
            Definition_Version_ = self.gds_validate_string(Definition_Version_, node, 'Definition_Version')
            self.Definition_Version = Definition_Version_
        elif nodeName_ == 'Classification_Name':
            Classification_Name_ = child_.text
            Classification_Name_ = self.gds_validate_string(Classification_Name_, node, 'Classification_Name')
            self.Classification_Name = Classification_Name_
        super(AVClassificationType, self).buildChildren(child_, node, nodeName_, True)
# end class AVClassificationType

class ProcessTreeNodeType(process_object.ProcessObjectType):
    """The ProcessTreeNodeType captures a single process, or node, in the
    process tree. It imports and extends the process_object.ProcessObjectType from
    the CybOX Process Object.The required id field specifies a
    unique ID for the Process Node. The ID must follow the pattern
    defined in the ProcessTreeNodeIDPattern simple type.The
    parent_action_idref field specifies the id of the action that
    created or injected this process."""
    subclass = None
    superclass = process_object.ProcessObjectType
    def __init__(self, object_reference=None, Custom_Properties=None, is_hidden=None, PID=None, Name=None, Creation_Time=None, Parent_PID=None, Child_PID_List=None, Image_Info=None, Argument_List=None, Environment_Variable_List=None, Kernel_Time=None, Port_List=None, Network_Connection_List=None, Start_Time=None, Status=None, Username=None, User_Time=None, Extracted_Features=None, id=None, parent_action_idref=None, ordinal_position=None, Initiated_Actions=None, Spawned_Process=None, Injected_Process=None):
        super(ProcessTreeNodeType, self).__init__(object_reference, Custom_Properties, is_hidden, PID, Name, Creation_Time, Parent_PID, Child_PID_List, Image_Info, Argument_List, Environment_Variable_List, Kernel_Time, Port_List, Network_Connection_List, Start_Time, Status, Username, User_Time, Extracted_Features, )
        self.id = _cast(None, id)
        self.parent_action_idref = _cast(None, parent_action_idref)
        self.ordinal_position = ordinal_position
        self.Initiated_Actions = Initiated_Actions
        if Spawned_Process is None:
            self.Spawned_Process = []
        else:
            self.Spawned_Process = Spawned_Process
        if Injected_Process is None:
            self.Injected_Process = []
        else:
            self.Injected_Process = Injected_Process
    def factory(*args_, **kwargs_):
        if ProcessTreeNodeType.subclass:
            return ProcessTreeNodeType.subclass(*args_, **kwargs_)
        else:
            return ProcessTreeNodeType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Initiated_Actions(self): return self.Initiated_Actions
    def set_Initiated_Actions(self, Initiated_Actions): self.Initiated_Actions = Initiated_Actions
    def get_Spawned_Process(self): return self.Spawned_Process
    def set_Spawned_Process(self, Spawned_Process): self.Spawned_Process = Spawned_Process
    def add_Spawned_Process(self, value): self.Spawned_Process.append(value)
    def insert_Spawned_Process(self, index, value): self.Spawned_Process[index] = value
    def get_Injected_Process(self): return self.Injected_Process
    def set_Injected_Process(self, Injected_Process): self.Injected_Process = Injected_Process
    def add_Injected_Process(self, value): self.Injected_Process.append(value)
    def insert_Injected_Process(self, index, value): self.Injected_Process[index] = value
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def get_parent_action_idref(self): return self.parent_action_idref
    def set_parent_action_idref(self, parent_action_idref): self.parent_action_idref = parent_action_idref
    def get_ordinal_position(self): return self.ordinal_position
    def set_ordinal_position(self, ordinal_position): self.ordinal_position = ordinal_position
    def hasContent_(self):
        if (
            self.Initiated_Actions is not None or
            self.Spawned_Process or
            self.Injected_Process or
            super(ProcessTreeNodeType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ProcessTreeNodeType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ProcessTreeNodeType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ProcessTreeNodeType'):
        super(ProcessTreeNodeType, self).exportAttributes(write, level, already_processed, namespace_, name_='ProcessTreeNodeType')
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
        if self.parent_action_idref is not None and 'parent_action_idref' not in already_processed:
            already_processed.add('parent_action_idref')
            write(' parent_action_idref=%s' % (quote_attrib(self.parent_action_idref), ))
        if self.ordinal_position is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            write(' ordinal_position=%s' % (quote_attrib(self.ordinal_position), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ProcessTreeNodeType', fromsubclass_=False, pretty_print=True):
        super(ProcessTreeNodeType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Initiated_Actions is not None:
            self.Initiated_Actions.export(write, level, 'maecBundle:', name_='Initiated_Actions', pretty_print=pretty_print)
        for Spawned_Process_ in self.Spawned_Process:
            Spawned_Process_.export(write, level, 'maecBundle:', name_='Spawned_Process', pretty_print=pretty_print)
        for Injected_Process_ in self.Injected_Process:
            Injected_Process_.export(write, level, 'maecBundle:', name_='Injected_Process', pretty_print=pretty_print)
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
        value = find_attr_value_('parent_action_idref', node)
        if value is not None and 'parent_action_idref' not in already_processed:
            already_processed.add('parent_action_idref')
            self.parent_action_idref = value
        value = find_attr_value_('ordinal_position', node)
        if value is not None and 'ordinal_position' not in already_processed:
            already_processed.add('ordinal_position')
            self.ordinal_position = value
        super(ProcessTreeNodeType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Initiated_Actions':
            obj_ = ActionReferenceListType.factory()
            obj_.build(child_)
            self.set_Initiated_Actions(obj_)
        elif nodeName_ == 'Spawned_Process':
            obj_ = ProcessTreeNodeType.factory()
            obj_.build(child_)
            self.Spawned_Process.append(obj_)
        elif nodeName_ == 'Injected_Process':
            obj_ = ProcessTreeNodeType.factory()
            obj_.build(child_)
            self.Injected_Process.append(obj_)
        super(ProcessTreeNodeType, self).buildChildren(child_, node, nodeName_, True)
# end class ProcessTreeNodeType

class BehavioralActionReferenceType(cybox_core.ActionReferenceType):
    """The BehavioralActionReferenceType defines an action reference that
    can be used as part of a Behavior.The behavioral_ordering field
    defines the ordering of the Action with respect to the other
    Actions that make up the Behavior. For example, an Action with a
    behavioral_ordering of "1" would come before an Action with a
    behavioral_ordering of "2", etc."""
    subclass = None
    superclass = cybox_core.ActionReferenceType
    def __init__(self, action_id=None, behavioral_ordering=None):
        super(BehavioralActionReferenceType, self).__init__(action_id, )
        self.behavioral_ordering = _cast(int, behavioral_ordering)
        pass
    def factory(*args_, **kwargs_):
        if BehavioralActionReferenceType.subclass:
            return BehavioralActionReferenceType.subclass(*args_, **kwargs_)
        else:
            return BehavioralActionReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_behavioral_ordering(self): return self.behavioral_ordering
    def set_behavioral_ordering(self, behavioral_ordering): self.behavioral_ordering = behavioral_ordering
    def hasContent_(self):
        if (
            super(BehavioralActionReferenceType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehavioralActionReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehavioralActionReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehavioralActionReferenceType'):
        super(BehavioralActionReferenceType, self).exportAttributes(write, level, already_processed, namespace_, name_='BehavioralActionReferenceType')
        if self.behavioral_ordering is not None and 'behavioral_ordering' not in already_processed:
            already_processed.add('behavioral_ordering')
            write(' behavioral_ordering="%s"' % self.gds_format_integer(self.behavioral_ordering, input_name='behavioral_ordering'))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehavioralActionReferenceType', fromsubclass_=False, pretty_print=True):
        super(BehavioralActionReferenceType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('behavioral_ordering', node)
        if value is not None and 'behavioral_ordering' not in already_processed:
            already_processed.add('behavioral_ordering')
            try:
                self.behavioral_ordering = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
            if self.behavioral_ordering <= 0:
                raise_parse_error(node, 'Invalid PositiveInteger')
        super(BehavioralActionReferenceType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        super(BehavioralActionReferenceType, self).buildChildren(child_, node, nodeName_, True)
        pass
# end class BehavioralActionReferenceType

class ObjectCollectionType(BaseCollectionType):
    """The ObjectCollectionType provides a mechanism for characterizing
    collections of Objects. For instance, it can be used to group
    all of the Objects that are associated with a specific
    behavior.The id attribute specifies a unique ID for this Object
    Collection. The ID must follow the pattern defined in the
    ObjectCollIDPattern simple type."""
    subclass = None
    superclass = BaseCollectionType
    def __init__(self, name=None, Affinity_Type=None, Affinity_Degree=None, Description=None, id=None, Object_List=None):
        super(ObjectCollectionType, self).__init__(name, Affinity_Type, Affinity_Degree, Description, )
        self.id = _cast(None, id)
        self.Object_List = Object_List
    def factory(*args_, **kwargs_):
        if ObjectCollectionType.subclass:
            return ObjectCollectionType.subclass(*args_, **kwargs_)
        else:
            return ObjectCollectionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Object_List(self): return self.Object_List
    def set_Object_List(self, Object_List): self.Object_List = Object_List
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Object_List is not None or
            super(ObjectCollectionType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ObjectCollectionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ObjectCollectionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ObjectCollectionType'):
        super(ObjectCollectionType, self).exportAttributes(write, level, already_processed, namespace_, name_='ObjectCollectionType')
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ObjectCollectionType', fromsubclass_=False, pretty_print=True):
        super(ObjectCollectionType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Object_List is not None:
            self.Object_List.export(write, level, 'maecBundle:', name_='Object_List', pretty_print=pretty_print)
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
        super(ObjectCollectionType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Object_List':
            obj_ = ObjectListType.factory()
            obj_.build(child_)
            self.set_Object_List(obj_)
        super(ObjectCollectionType, self).buildChildren(child_, node, nodeName_, True)
# end class ObjectCollectionType

class ActionCollectionType(BaseCollectionType):
    """The ActionCollectionType provides a method for characterizing
    collections of actions. This can be useful for organizing
    actions that may be related and where the exact relationship is
    unknown, as well as actions whose associated behavior has not
    yet been established.The id field specifies a unique ID for this
    Action Collection. The ID must follow the pattern defined in the
    ActionCollIDPattern simple type."""
    subclass = None
    superclass = BaseCollectionType
    def __init__(self, name=None, Affinity_Type=None, Affinity_Degree=None, Description=None, id=None, Action_List=None):
        super(ActionCollectionType, self).__init__(name, Affinity_Type, Affinity_Degree, Description, )
        self.id = _cast(None, id)
        self.Action_List = Action_List
    def factory(*args_, **kwargs_):
        if ActionCollectionType.subclass:
            return ActionCollectionType.subclass(*args_, **kwargs_)
        else:
            return ActionCollectionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Action_List(self): return self.Action_List
    def set_Action_List(self, Action_List): self.Action_List = Action_List
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Action_List is not None or
            super(ActionCollectionType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='ActionCollectionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='ActionCollectionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='ActionCollectionType'):
        super(ActionCollectionType, self).exportAttributes(write, level, already_processed, namespace_, name_='ActionCollectionType')
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='ActionCollectionType', fromsubclass_=False, pretty_print=True):
        super(ActionCollectionType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Action_List is not None:
            self.Action_List.export(write, level, 'maecBundle:', name_='Action_List', pretty_print=pretty_print)
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
        super(ActionCollectionType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Action_List':
            obj_ = ActionListType.factory()
            obj_.build(child_)
            self.set_Action_List(obj_)
        super(ActionCollectionType, self).buildChildren(child_, node, nodeName_, True)
# end class ActionCollectionType

class BehaviorCollectionType(BaseCollectionType):
    """The BehaviorCollectionType provides a mechanism for characterizing
    collections of behaviors.The id field specifies a unique ID for
    this Behavior Collection. The ID must follow the pattern defined
    in the BehaviorCollIDPattern simple type."""
    subclass = None
    superclass = BaseCollectionType
    def __init__(self, name=None, Affinity_Type=None, Affinity_Degree=None, Description=None, id=None, Purpose=None, Behavior_List=None):
        super(BehaviorCollectionType, self).__init__(name, Affinity_Type, Affinity_Degree, Description, )
        self.id = _cast(None, id)
        self.Purpose = Purpose
        self.Behavior_List = Behavior_List
    def factory(*args_, **kwargs_):
        if BehaviorCollectionType.subclass:
            return BehaviorCollectionType.subclass(*args_, **kwargs_)
        else:
            return BehaviorCollectionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Purpose(self): return self.Purpose
    def set_Purpose(self, Purpose): self.Purpose = Purpose
    def get_Behavior_List(self): return self.Behavior_List
    def set_Behavior_List(self, Behavior_List): self.Behavior_List = Behavior_List
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Purpose is not None or
            self.Behavior_List is not None or
            super(BehaviorCollectionType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehaviorCollectionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehaviorCollectionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehaviorCollectionType'):
        super(BehaviorCollectionType, self).exportAttributes(write, level, already_processed, namespace_, name_='BehaviorCollectionType')
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehaviorCollectionType', fromsubclass_=False, pretty_print=True):
        super(BehaviorCollectionType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Purpose is not None:
            write('<%sPurpose>%s</%sPurpose>%s' % ('maecBundle:', quote_xml(self.Purpose), 'maecBundle:', eol_))
        if self.Behavior_List is not None:
            self.Behavior_List.export(write, level, 'maecBundle:', name_='Behavior_List', pretty_print=pretty_print)
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
        super(BehaviorCollectionType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Purpose':
            obj_ = BehaviorPurposeType.factory()
            obj_.build(child_)
            self.set_Purpose(obj_)
        elif nodeName_ == 'Behavior_List':
            obj_ = BehaviorListType.factory()
            obj_.build(child_)
            self.set_Behavior_List(obj_)
        super(BehaviorCollectionType, self).buildChildren(child_, node, nodeName_, True)
# end class BehaviorCollectionType

class MalwareActionType(cybox_core.ActionType):
    """The MalwareActionType is one of the foundational MAEC types, and
    serves as a method for the characterization of actions found or
    observed in malware. Actions can be thought of as system state
    changes and similar operations that represent the fundamental
    low-level operation of malware. Some examples include the
    creation of a file, deletion of a registry key, and the sending
    of some data on a socket. It imports and extends the CybOX
    cybox_core.ActionType. For MAEC, the id attribute is required and must
    follow the proper syntax: A dash-delimited format is used with
    the id or idref starting with the word maec followed by a unique
    string, followed by the three letter code 'act', and ending with
    an integer."""
    subclass = None
    superclass = cybox_core.ActionType
    def __init__(self, timestamp=None, action_status=None, ordinal_position=None, context=None, idref=None, id=None, Type=None, Name=None, Description=None, Action_Aliases=None, Action_Arguments=None, Discovery_Method=None, Associated_Objects=None, Relationships=None, Frequency=None, Implementation=None, extensiontype_=None):
        super(MalwareActionType, self).__init__(timestamp, action_status, ordinal_position, context, idref, id, Type, Name, Description, Action_Aliases, Action_Arguments, Discovery_Method, Associated_Objects, Relationships, Frequency)
        self.Implementation = Implementation
        self.extensiontype_ = extensiontype_
    def factory(*args_, **kwargs_):
        if MalwareActionType.subclass:
            return MalwareActionType.subclass(*args_, **kwargs_)
        else:
            return MalwareActionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Implementation(self): return self.Implementation
    def set_Implementation(self, Implementation): self.Implementation = Implementation
    def get_extensiontype_(self): return self.extensiontype_
    def set_extensiontype_(self, extensiontype_): self.extensiontype_ = extensiontype_
    def hasContent_(self):
        if (
            self.Implementation is not None or
            super(MalwareActionType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='MalwareActionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MalwareActionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='MalwareActionType'):
        super(MalwareActionType, self).exportAttributes(write, level, already_processed, namespace_, name_='MalwareActionType')
        if self.extensiontype_ is not None and 'xsi:type' not in already_processed:
            already_processed.add('xsi:type')
            write(' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')
            write(' xsi:type="%s"' % self.extensiontype_)
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='MalwareActionType', fromsubclass_=False, pretty_print=True):
        super(MalwareActionType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Implementation is not None:
            self.Implementation.export(write, level, 'maecBundle:', name_='Implementation', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('xsi:type', node)
        if value is not None and 'xsi:type' not in already_processed:
            already_processed.add('xsi:type')
            self.extensiontype_ = value
        super(MalwareActionType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Implementation':
            obj_ = ActionImplementationType.factory()
            obj_.build(child_)
            self.set_Implementation(obj_)
        super(MalwareActionType, self).buildChildren(child_, node, nodeName_, True)
# end class MalwareActionType

class BehavioralActionType(MalwareActionType):
    """The BehavioralActionType defines an Action that can be used as part
    of a Behavior.The behavioral_ordering field defines the ordering
    of the Action with respect to the other Actions that make up the
    behavior. So an action with a behavioral_ordering of "1" would
    come before an Action with a behavioral_ordering of "2", etc."""
    subclass = None
    superclass = MalwareActionType
    def __init__(self, timestamp=None, action_status=None, ordinal_position=None, context=None, idref=None, id=None, Type=None, Name=None, Description=None, Action_Aliases=None, Action_Arguments=None, Discovery_Method=None, Associated_Objects=None, Relationships=None, Frequency=None, Implementation=None, behavioral_ordering=None):
        super(BehavioralActionType, self).__init__(timestamp, action_status, ordinal_position, context, idref, id, Type, Name, Description, Action_Aliases, Action_Arguments, Discovery_Method, Associated_Objects, Relationships, Frequency, Implementation, )
        self.behavioral_ordering = _cast(int, behavioral_ordering)
        pass
    def factory(*args_, **kwargs_):
        if BehavioralActionType.subclass:
            return BehavioralActionType.subclass(*args_, **kwargs_)
        else:
            return BehavioralActionType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_behavioral_ordering(self): return self.behavioral_ordering
    def set_behavioral_ordering(self, behavioral_ordering): self.behavioral_ordering = behavioral_ordering
    def hasContent_(self):
        if (
            super(BehavioralActionType, self).hasContent_()
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='BehavioralActionType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='BehavioralActionType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='BehavioralActionType'):
        super(BehavioralActionType, self).exportAttributes(write, level, already_processed, namespace_, name_='BehavioralActionType')
        if self.behavioral_ordering is not None and 'behavioral_ordering' not in already_processed:
            already_processed.add('behavioral_ordering')
            write(' behavioral_ordering="%s"' % self.gds_format_integer(self.behavioral_ordering, input_name='behavioral_ordering'))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='BehavioralActionType', fromsubclass_=False, pretty_print=True):
        super(BehavioralActionType, self).exportChildren(write, level, 'maecBundle:', name_, True, pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('behavioral_ordering', node)
        if value is not None and 'behavioral_ordering' not in already_processed:
            already_processed.add('behavioral_ordering')
            try:
                self.behavioral_ordering = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
            if self.behavioral_ordering <= 0:
                raise_parse_error(node, 'Invalid PositiveInteger')
        super(BehavioralActionType, self).buildAttributes(node, attrs, already_processed)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        super(BehavioralActionType, self).buildChildren(child_, node, nodeName_, True)
        pass
# end class BehavioralActionType

class CapabilityType(GeneratedsSuper):
    """The CapabilityType captures details of a Capability that may be
    implemented in the malware instance, along with its child
    Strategic and Tactical Objectives.The required id field
    specifies a unique ID for this MAEC Capability.The name field
    captures the name of the Capability. It uses the
    MalwareCapabilityEnum-1.0 enumeration from the MAEC Vocabularies
    schema."""
    subclass = None
    superclass = None
    def __init__(self, id=None, name=None, Description=None, Property=None, Strategic_Objective=None, Tactical_Objective=None, Behavior_Reference=None, Relationship=None):
        self.id = _cast(None, id)
        self.name = _cast(None, name)
        self.Description = Description
        if Property is None:
            self.Property = []
        else:
            self.Property = Property
        if Strategic_Objective is None:
            self.Strategic_Objective = []
        else:
            self.Strategic_Objective = Strategic_Objective
        if Tactical_Objective is None:
            self.Tactical_Objective = []
        else:
            self.Tactical_Objective = Tactical_Objective
        if Behavior_Reference is None:
            self.Behavior_Reference = []
        else:
            self.Behavior_Reference = Behavior_Reference
        if Relationship is None:
            self.Relationship = []
        else:
            self.Relationship = Relationship
    def factory(*args_, **kwargs_):
        if CapabilityType.subclass:
            return CapabilityType.subclass(*args_, **kwargs_)
        else:
            return CapabilityType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_Property(self): return self.Property
    def set_Property(self, Property): self.Property = Property
    def add_Property(self, value): self.Property.append(value)
    def insert_Property(self, index, value): self.Property[index] = value
    def get_Strategic_Objective(self): return self.Strategic_Objective
    def set_Strategic_Objective(self, Strategic_Objective): self.Strategic_Objective = Strategic_Objective
    def add_Strategic_Objective(self, value): self.Strategic_Objective.append(value)
    def insert_Strategic_Objective(self, index, value): self.Strategic_Objective[index] = value
    def get_Tactical_Objective(self): return self.Tactical_Objective
    def set_Tactical_Objective(self, Tactical_Objective): self.Tactical_Objective = Tactical_Objective
    def add_Tactical_Objective(self, value): self.Tactical_Objective.append(value)
    def insert_Tactical_Objective(self, index, value): self.Tactical_Objective[index] = value
    def get_Behavior_Reference(self): return self.Behavior_Reference
    def set_Behavior_Reference(self, Behavior_Reference): self.Behavior_Reference = Behavior_Reference
    def add_Behavior_Reference(self, value): self.Behavior_Reference.append(value)
    def insert_Behavior_Reference(self, index, value): self.Behavior_Reference[index] = value
    def get_Relationship(self): return self.Relationship
    def set_Relationship(self, Relationship): self.Relationship = Relationship
    def add_Relationship(self, value): self.Relationship.append(value)
    def insert_Relationship(self, index, value): self.Relationship[index] = value
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def get_name(self): return self.name
    def set_name(self, name): self.name = name
    def hasContent_(self):
        if (
            self.Description is not None or
            self.Property or
            self.Strategic_Objective or
            self.Tactical_Objective or
            self.Behavior_Reference or
            self.Relationship
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityType'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
        if self.name is not None and 'name' not in already_processed:
            already_processed.add('name')
            write(' name=%s' % (quote_attrib(self.name), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
        for Property_ in self.Property:
            Property_.export(write, level, 'maecBundle:', name_='Property', pretty_print=pretty_print)
        for Strategic_Objective_ in self.Strategic_Objective:
            Strategic_Objective_.export(write, level, 'maecBundle:', name_='Strategic_Objective', pretty_print=pretty_print)
        for Tactical_Objective_ in self.Tactical_Objective:
            Tactical_Objective_.export(write, level, 'maecBundle:', name_='Tactical_Objective', pretty_print=pretty_print)
        for Behavior_Reference_ in self.Behavior_Reference:
            Behavior_Reference_.export(write, level, 'maecBundle:', name_='Behavior_Reference', pretty_print=pretty_print)
        for Relationship_ in self.Relationship:
            Relationship_.export(write, level, 'maecBundle:', name_='Relationship', pretty_print=pretty_print)
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
        value = find_attr_value_('name', node)
        if value is not None and 'name' not in already_processed:
            already_processed.add('name')
            self.name = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
        elif nodeName_ == 'Property':
            obj_ = CapabilityPropertyType.factory()
            obj_.build(child_)
            self.Property.append(obj_)
        elif nodeName_ == 'Strategic_Objective':
            obj_ = CapabilityObjectiveType.factory()
            obj_.build(child_)
            self.Strategic_Objective.append(obj_)
        elif nodeName_ == 'Tactical_Objective':
            obj_ = CapabilityObjectiveType.factory()
            obj_.build(child_)
            self.Tactical_Objective.append(obj_)
        elif nodeName_ == 'Behavior_Reference':
            obj_ = BehaviorReferenceType.factory()
            obj_.build(child_)
            self.Behavior_Reference.append(obj_)
        elif nodeName_ == 'Relationship':
            obj_ = BehaviorRelationshipType.factory()
            obj_.build(child_)
            self.Relationship.append(obj_)
# end class CapabilityType

class CapabilityListType(GeneratedsSuper):
    """The CapabilityListType captures a list of Capabilities."""
    subclass = None
    superclass = None
    def __init__(self, Capability=None, Capability_Reference=None):
        if Capability is None:
            self.Capability = []
        else:
            self.Capability = Capability
        if Capability_Reference is None:
            self.Capability_Reference = []
        else:
            self.Capability_Reference = Capability_Reference
    def factory(*args_, **kwargs_):
        if CapabilityListType.subclass:
            return CapabilityListType.subclass(*args_, **kwargs_)
        else:
            return CapabilityListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Capability(self): return self.Capability
    def set_Capability(self, Capability): self.Capability = Capability
    def add_Capability(self, value): self.Capability.append(value)
    def insert_Capability(self, index, value): self.Capability[index] = value
    def get_Capability_Reference(self): return self.Capability_Reference
    def set_Capability_Reference(self, Capability_Reference): self.Capability_Reference = Capability_Reference
    def add_Capability_Reference(self, value): self.Capability_Reference.append(value)
    def insert_Capability_Reference(self, index, value): self.Capability_Reference[index] = value
    def hasContent_(self):
        if (
            self.Capability or
            self.Capability_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Capability_ in self.Capability:
            Capability_.export(write, level, 'maecBundle:', name_='Capability', pretty_print=pretty_print)
        for Capability_Reference_ in self.Capability_Reference:
            Capability_Reference_.export(write, level, 'maecBundle:', name_='Capability_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Capability':
            obj_ = CapabilityType.factory()
            obj_.build(child_)
            self.Capability.append(obj_)
        elif nodeName_ == 'Capability_Reference':
            obj_ = CapabilityReferenceType.factory()
            obj_.build(child_)
            self.Capability_Reference.append(obj_)
# end class CapabilityListType

class CapabilityReferenceType(GeneratedsSuper):
    """The CapabilityReferenceType serves as a method for referencing
    existing Capabilities contained in the MAEC document.The
    capability_idref field references the ID of a Capability
    contained inside the current MAEC document."""
    subclass = None
    superclass = None
    def __init__(self, capability_idref=None):
        self.capability_idref = _cast(None, capability_idref)
        pass
    def factory(*args_, **kwargs_):
        if CapabilityReferenceType.subclass:
            return CapabilityReferenceType.subclass(*args_, **kwargs_)
        else:
            return CapabilityReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_capability_idref(self): return self.capability_idref
    def set_capability_idref(self, capability_idref): self.capability_idref = capability_idref
    def hasContent_(self):
        if (
            self.capability_idref is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityReferenceType'):
        if self.capability_idref is not None and 'capability_idref' not in already_processed:
            already_processed.add('capability_idref')
            write(' capability_idref=%s' % (quote_attrib(self.capability_idref), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityReferenceType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('capability_idref', node)
        if value is not None and 'capability_idref' not in already_processed:
            already_processed.add('capability_idref')
            self.capability_idref = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class CapabilityReferenceType

class CapabilityObjectiveType(GeneratedsSuper):
    """The CapabilityObjectiveType captures details of a Capability
    Strategic or Tactical Objective may be implemented in the
    malware instance and its properties.The required id field
    specifies a unique ID for this Capability Objective."""
    subclass = None
    superclass = None
    def __init__(self, id=None, Name=None, Description=None, Property=None, Behavior_Reference=None, Relationship=None):
        self.id = _cast(None, id)
        self.Name = Name
        self.Description = Description
        if Property is None:
            self.Property = []
        else:
            self.Property = Property
        if Behavior_Reference is None:
            self.Behavior_Reference = []
        else:
            self.Behavior_Reference = Behavior_Reference
        if Relationship is None:
            self.Relationship = []
        else:
            self.Relationship = Relationship
    def factory(*args_, **kwargs_):
        if CapabilityObjectiveType.subclass:
            return CapabilityObjectiveType.subclass(*args_, **kwargs_)
        else:
            return CapabilityObjectiveType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Name(self): return self.Name
    def set_Name(self, Name): self.Name = Name
    def get_Description(self): return self.Description
    def set_Description(self, Description): self.Description = Description
    def get_Property(self): return self.Property
    def set_Property(self, Property): self.Property = Property
    def add_Property(self, value): self.Property.append(value)
    def insert_Property(self, index, value): self.Property[index] = value
    def get_Behavior_Reference(self): return self.Behavior_Reference
    def set_Behavior_Reference(self, Behavior_Reference): self.Behavior_Reference = Behavior_Reference
    def add_Behavior_Reference(self, value): self.Behavior_Reference.append(value)
    def insert_Behavior_Reference(self, index, value): self.Behavior_Reference[index] = value
    def get_Relationship(self): return self.Relationship
    def set_Relationship(self, Relationship): self.Relationship = Relationship
    def add_Relationship(self, value): self.Relationship.append(value)
    def insert_Relationship(self, index, value): self.Relationship[index] = value
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def hasContent_(self):
        if (
            self.Name is not None or
            self.Description is not None or
            self.Property or
            self.Behavior_Reference or
            self.Relationship
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityObjectiveType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityObjectiveType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityObjectiveType'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityObjectiveType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Name is not None:
            self.Name.export(write, level, 'maecBundle:', name_='Name', pretty_print=pretty_print)
        if self.Description is not None:
            showIndent(write, level, pretty_print)
            write('<%sDescription>%s</%sDescription>%s' % ('maecBundle:', quote_xml(self.Description), 'maecBundle:', eol_))
        for Property_ in self.Property:
            Property_.export(write, level, 'maecBundle:', name_='Property', pretty_print=pretty_print)
        for Behavior_Reference_ in self.Behavior_Reference:
            Behavior_Reference_.export(write, level, 'maecBundle:', name_='Behavior_Reference', pretty_print=pretty_print)
        for Relationship_ in self.Relationship:
            Relationship_.export(write, level, 'maecBundle:', name_='Relationship', pretty_print=pretty_print)
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
        if nodeName_ == 'Name':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Name(obj_)
        elif nodeName_ == 'Description':
            Description_ = child_.text
            Description_ = self.gds_validate_string(Description_, node, 'Description')
            self.Description = Description_
        elif nodeName_ == 'Property':
            obj_ = CapabilityPropertyType.factory()
            obj_.build(child_)
            self.Property.append(obj_)
        elif nodeName_ == 'Behavior_Reference':
            obj_ = BehaviorReferenceType.factory()
            obj_.build(child_)
            self.Behavior_Reference.append(obj_)
        elif nodeName_ == 'Relationship':
            obj_ = CapabilityObjectiveRelationshipType.factory()
            obj_.build(child_)
            self.Relationship.append(obj_)
# end class CapabilityObjectiveType

class CapabilityRelationshipType(GeneratedsSuper):
    """The CapabilityObjectiveRelationshipType captures a relationship
    between a Capability and one or more other Capabilitys."""
    subclass = None
    superclass = None
    def __init__(self, Relationship_Type=None, Capability_Reference=None):
        self.Relationship_Type = Relationship_Type
        if Capability_Reference is None:
            self.Capability_Reference = []
        else:
            self.Capability_Reference = Capability_Reference
    def factory(*args_, **kwargs_):
        if CapabilityRelationshipType.subclass:
            return CapabilityRelationshipType.subclass(*args_, **kwargs_)
        else:
            return CapabilityRelationshipType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Relationship_Type(self): return self.Relationship_Type
    def set_Relationship_Type(self, Relationship_Type): self.Relationship_Type = Relationship_Type
    def get_Capability_Reference(self): return self.Capability_Reference
    def set_Capability_Reference(self, Capability_Reference): self.Capability_Reference = Capability_Reference
    def add_Capability_Reference(self, value): self.Capability_Reference.append(value)
    def insert_Capability_Reference(self, index, value): self.Capability_Reference[index] = value
    def hasContent_(self):
        if (
            self.Relationship_Type is not None or
            self.Capability_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityRelationshipType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityRelationshipType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityRelationshipType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityRelationshipType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Relationship_Type is not None:
            self.Relationship_Type.export(write, level, 'maecBundle:', name_='Relationship_Type', pretty_print=pretty_print)
        for Capability_Reference_ in self.Capability_Reference:
            Capability_Reference_.export(write, level, 'maecBundle:', name_='Capability_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Relationship_Type':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Relationship_Type(obj_)
        elif nodeName_ == 'Capability_Reference':
            obj_ = CapabilityReferenceType.factory()
            obj_.build(child_)
            self.Capability_Reference.append(obj_)
# end class CapabilityRelationshipType

class CapabilityObjectiveRelationshipType(GeneratedsSuper):
    """The CapabilityObjectiveRelationshipType captures a relationship
    between a Strategic or Tactical Objective and one or more other
    Strategic or Tactical Objectives."""
    subclass = None
    superclass = None
    def __init__(self, Relationship_Type=None, Objective_Reference=None):
        self.Relationship_Type = Relationship_Type
        if Objective_Reference is None:
            self.Objective_Reference = []
        else:
            self.Objective_Reference = Objective_Reference
    def factory(*args_, **kwargs_):
        if CapabilityObjectiveRelationshipType.subclass:
            return CapabilityObjectiveRelationshipType.subclass(*args_, **kwargs_)
        else:
            return CapabilityObjectiveRelationshipType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Relationship_Type(self): return self.Relationship_Type
    def set_Relationship_Type(self, Relationship_Type): self.Relationship_Type = Relationship_Type
    def get_Objective_Reference(self): return self.Objective_Reference
    def set_Objective_Reference(self, Objective_Reference): self.Objective_Reference = Objective_Reference
    def add_Objective_Reference(self, value): self.Objective_Reference.append(value)
    def insert_Objective_Reference(self, index, value): self.Objective_Reference[index] = value
    def hasContent_(self):
        if (
            self.Relationship_Type is not None or
            self.Objective_Reference
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityObjectiveRelationshipType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityObjectiveRelationshipType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityObjectiveRelationshipType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityObjectiveRelationshipType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Relationship_Type is not None:
            self.Relationship_Type.export(write, level, 'maecBundle:', name_='Relationship_Type', pretty_print=pretty_print)
        for Objective_Reference_ in self.Objective_Reference:
            Objective_Reference_.export(write, level, 'maecBundle:', name_='Objective_Reference', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Relationship_Type':
            obj_ = cybox_common.ControlledVocabularyStringType.factory()
            obj_.build(child_)
            self.set_Relationship_Type(obj_)
        elif nodeName_ == 'Objective_Reference':
            obj_ = CapabilityObjectiveReferenceType.factory()
            obj_.build(child_)
            self.Objective_Reference.append(obj_)
# end class CapabilityObjectiveRelationshipType

class CapabilityObjectiveReferenceType(GeneratedsSuper):
    """The CapabilityObjectiveReferenceType serves as a method for
    referencing existing Capability Objectives (either Strategic or
    Tactical) contained in the Bundle.The objective_idref field
    references the ID of a Capability Objective (either Strategic or
    Tactical) contained inside the current MAEC document."""
    subclass = None
    superclass = None
    def __init__(self, objective_idref=None):
        self.objective_idref = _cast(None, objective_idref)
        pass
    def factory(*args_, **kwargs_):
        if CapabilityObjectiveReferenceType.subclass:
            return CapabilityObjectiveReferenceType.subclass(*args_, **kwargs_)
        else:
            return CapabilityObjectiveReferenceType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_objective_idref(self): return self.objective_idref
    def set_objective_idref(self, objective_idref): self.objective_idref = objective_idref
    def hasContent_(self):
        if (

            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityObjectiveReferenceType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityObjectiveReferenceType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityObjectiveReferenceType'):
        if self.objective_idref is not None and 'objective_idref' not in already_processed:
            already_processed.add('objective_idref')
            write(' objective_idref=%s' % (quote_attrib(self.objective_idref), ))
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityObjectiveReferenceType', fromsubclass_=False, pretty_print=True):
        pass
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('objective_idref', node)
        if value is not None and 'objective_idref' not in already_processed:
            already_processed.add('objective_idref')
            self.objective_idref = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class CapabilityObjectiveReferenceType

class CapabilityPropertyType(GeneratedsSuper):
    """The CapabilityPropertyType captures a single property of a
    Capability or Capability Objective."""
    subclass = None
    superclass = None
    def __init__(self, Name=None, Value=None):
        self.Name = Name
        self.Value = Value
    def factory(*args_, **kwargs_):
        if CapabilityPropertyType.subclass:
            return CapabilityPropertyType.subclass(*args_, **kwargs_)
        else:
            return CapabilityPropertyType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Name(self): return self.Name
    def set_Name(self, Name): self.Name = Name
    def get_Value(self): return self.Value
    def set_Value(self, Value): self.Value = Value
    def validate_StringObjectPropertyType(self, value):
        # Validate type cybox_common.StringObjectPropertyType, a restriction on None.
        pass
    def hasContent_(self):
        if (
            self.Name is not None or
            self.Value is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecBundle:', name_='CapabilityPropertyType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='CapabilityPropertyType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecBundle:', name_='CapabilityPropertyType'):
        pass
    def exportChildren(self, write, level, namespace_='maecBundle:', name_='CapabilityPropertyType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Name is not None:
            self.Name.export(write, level, 'maecBundle:', name_='Name', pretty_print=pretty_print)
        if self.Value is not None:
            self.Value.export(write, level, 'maecBundle:', name_='Value', pretty_print=pretty_print)
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
            obj_ = cybox_common.StringObjectPropertyType.factory()
            obj_.build(child_)
            self.set_Value(obj_)
# end class CapabilityPropertyType

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
    #rootObj.export(sys.stdout, 0, name_="MAEC_Bundle",
    #    namespacedef_='')
    return rootObj

def parseLiteral(inFileName):
    doc = parsexml_(inFileName)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('#from maec_bundle_temp import *\n\n')
    sys.stdout.write('from datetime import datetime as datetime_\n\n')
    sys.stdout.write('import maec_bundle_temp as model_\n\n')
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
    "MalwareActionType",
    "BehaviorType",
    "BundleType",
    "BehaviorCollectionType",
    "ActionCollectionType",
    "APICallType",
    "ActionImplementationType",
    "CVEVulnerabilityType",
    "ObjectCollectionType",
    "BaseCollectionType",
    "BehaviorRelationshipType",
    "AVClassificationsType",
    "ParameterType",
    "ParameterListType",
    "AssociatedCodeType",
    "BehaviorPurposeType",
    "PlatformListType",
    "ExploitType",
    "BehaviorRelationshipListType",
    "BehavioralActionsType",
    "BehaviorListType",
    "ActionListType",
    "ObjectListType",
    "BehaviorReferenceType",
    "ObjectReferenceType",
    "BehavioralActionType",
    "BehavioralActionReferenceType",
    "BehavioralActionEquivalenceReferenceType",
    "BehaviorReferenceListType",
    "ActionReferenceListType",
    "ObjectReferenceListType",
    "CandidateIndicatorType",
    "CandidateIndicatorListType",
    "MalwareEntityType",
    "CollectionsType",
    "BundleReferenceType",
    "ProcessTreeType",
    "ProcessTreeNodeType",
    "CandidateIndicatorCompositionType",
    "CandidateIndicatorCollectionType",
    "CandidateIndicatorCollectionListType",
    "BehaviorCollectionListType",
    "ActionCollectionListType",
    "ObjectCollectionListType",
    "AVClassificationType"
    ]

GDSClassesMapping = {
    "MalwareActionType": MalwareActionType,
    "MAEC_Bundle": BundleType,
    "BehaviorType": BehaviorType,
    "BehaviorCollectionType": BehaviorCollectionType,
    "ActionCollectionType": ActionCollectionType,
    "APICallType": APICallType,
    "ActionImplementationType": ActionImplementationType,
    "CVEVulnerabilityType": CVEVulnerabilityType,
    "ObjectCollectionType": ObjectCollectionType,
    "BaseCollectionType": BaseCollectionType,
    "BehaviorRelationshipType": BehaviorRelationshipType,
    "AVClassificationsType": AVClassificationsType,
    "ParameterType": ParameterType,
    "ParameterListType": ParameterListType,
    "AssociatedCodeType": AssociatedCodeType,
    "BehaviorPurposeType": BehaviorPurposeType,
    "PlatformListType": PlatformListType,
    "ExploitType": ExploitType,
    "BehaviorRelationshipListType": BehaviorRelationshipListType,
    "BehavioralActionsType": BehavioralActionsType,
    "BehaviorListType": BehaviorListType,
    "ActionListType": ActionListType,
    "ObjectListType": ObjectListType,
    "BehaviorReferenceType": BehaviorReferenceType,
    "ObjectReferenceType": ObjectReferenceType,
    "BehavioralActionType": BehavioralActionType,
    "BehavioralActionReferenceType": BehavioralActionReferenceType,
    "BehavioralActionEquivalenceReferenceType": BehavioralActionEquivalenceReferenceType,
    "BehaviorReferenceListType": BehaviorReferenceListType,
    "ActionReferenceListType": ActionReferenceListType,
    "ObjectReferenceListType": ObjectReferenceListType,
    "CandidateIndicatorType": CandidateIndicatorType,
    "CandidateIndicatorListType": CandidateIndicatorListType,
    "MalwareEntityType": MalwareEntityType,
    "CollectionsType": CollectionsType,
    "BundleReferenceType": BundleReferenceType,
    "ProcessTreeType": ProcessTreeType,
    "ProcessTreeNodeType": ProcessTreeNodeType,
    "CandidateIndicatorCompositionType": CandidateIndicatorCompositionType,
    "CandidateIndicatorCollectionType": CandidateIndicatorCollectionType,
    "CandidateIndicatorCollectionListType": CandidateIndicatorCollectionListType,
    "BehaviorCollectionListType": BehaviorCollectionListType,
    "ActionCollectionListType": ActionCollectionListType,
    "ObjectCollectionListType": ObjectCollectionListType,
    "AVClassificationType": AVClassificationType
}
