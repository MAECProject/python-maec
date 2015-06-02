# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys

from mixbox.binding_utils import *

from maec.bindings import maec_package as maec_package_schema

class ContainerType(GeneratedsSuper):
    """The ContainerType encompasses all forms of MAEC data. Currently,
    this entails a list of Packages.The required id attribute
    specifies a unique ID for this Container. The ID must follow the
    pattern defined in the ContainerIDPattern simple type.The
    required schema_version attribute specifies the version of the
    MAEC Container Schema that the document has been written in and
    that should be used for validation.The timestamp attribute
    specifies the date/time that the Container was generated."""
    subclass = None
    superclass = None
    def __init__(self, timestamp=None, id=None, schema_version=None, Packages=None):
        self.timestamp = _cast(None, timestamp)
        self.id = _cast(None, id)
        self.schema_version = schema_version
        self.Packages = Packages
    def factory(*args_, **kwargs_):
        if ContainerType.subclass:
            return ContainerType.subclass(*args_, **kwargs_)
        else:
            return ContainerType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Packages(self): return self.Packages
    def set_Packages(self, Packages): self.Packages = Packages
    def get_timestamp(self): return self.timestamp
    def set_timestamp(self, timestamp): self.timestamp = timestamp
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def get_schema_version(self): return self.schema_version
    def set_schema_version(self, schema_version): self.schema_version = schema_version
    def hasContent_(self):
        if (
            self.Packages is not None
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecContainer:', name_='MAEC_Container', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='MAEC_Container')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecContainer:', name_='MAEC_Container'):
        if self.timestamp is not None and 'timestamp' not in already_processed:
            already_processed.add('timestamp')
            write(' timestamp="%s"' % self.gds_format_datetime(self.timestamp, input_name='timestamp'))
        if self.id is not None and 'id' not in already_processed:
            already_processed.add('id')
            write(' id=%s' % (quote_attrib(self.id), ))
        if self.schema_version is not None and 'schema_version' not in already_processed:
            already_processed.add('schema_version')
            write(' schema_version="%s"' % self.schema_version)
    def exportChildren(self, write, level, namespace_='maecContainer:', name_='MAEC_Container', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        if self.Packages is not None:
            self.Packages.export(write, level, 'maecContainer:', name_='Packages', pretty_print=pretty_print)
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
        if nodeName_ == 'Packages':
            obj_ = PackageListType.factory()
            obj_.build(child_)
            self.set_Packages(obj_)
# end class ContainerType

class PackageListType(GeneratedsSuper):
    """The PackageListType captures a list of Packages."""
    subclass = None
    superclass = None
    def __init__(self, Package=None):
        if Package is None:
            self.Package = []
        else:
            self.Package = Package
    def factory(*args_, **kwargs_):
        if PackageListType.subclass:
            return PackageListType.subclass(*args_, **kwargs_)
        else:
            return PackageListType(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_Package(self): return self.Package
    def set_Package(self, Package): self.Package = Package
    def add_Package(self, value): self.Package.append(value)
    def insert_Package(self, index, value): self.Package[index] = value
    def hasContent_(self):
        if (
            self.Package
            ):
            return True
        else:
            return False
    def export(self, write, level, namespace_='maecContainer:', name_='PackageListType', namespacedef_='', pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        showIndent(write, level, pretty_print)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = set()
        self.exportAttributes(write, level, already_processed, namespace_, name_='PackageListType')
        if self.hasContent_():
            write('>%s' % (eol_, ))
            self.exportChildren(write, level + 1, namespace_, name_, pretty_print=pretty_print)
            showIndent(write, level, pretty_print)
            write('</%s%s>%s' % (namespace_, name_, eol_))
        else:
            write('/>%s' % (eol_, ))
    def exportAttributes(self, write, level, already_processed, namespace_='maecContainer:', name_='PackageListType'):
        pass
    def exportChildren(self, write, level, namespace_='maecContainer:', name_='PackageListType', fromsubclass_=False, pretty_print=True):
        if pretty_print:
            eol_ = '\n'
        else:
            eol_ = ''
        for Package_ in self.Package:
            Package_.export(write, level, 'maecContainer:', name_='Package', pretty_print=pretty_print)
    def build(self, node):
        already_processed = set()
        self.buildAttributes(node, node.attrib, already_processed)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'Package':
            obj_ = maec_package_schema.PackageType.factory()
            obj_.build(child_)
            self.Package.append(obj_)
# end class PackageListType

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
    #rootObj.export(sys.stdout, 0, name_="MAEC_Container",
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
    sys.stdout.write('#from maec_container_temp import *\n\n')
    sys.stdout.write('from datetime import datetime as datetime_\n\n')
    sys.stdout.write('import maec_container_temp as model_\n\n')
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
    "ContainerType",
    "PackageListType"
    ]

GDSClassesMapping = {
    "ContainerType": ContainerType,
    "PackageListType": PackageListType              
}
