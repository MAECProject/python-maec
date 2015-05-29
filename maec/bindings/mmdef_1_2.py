# -*- coding: utf-8 -*-
# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys

from mixbox.binding_utils import *

class malwareMetaData(GeneratedsSuper):
    """This is the top level element for the xml document. Required
    attribute is version. Open issues: 2. Right way to express
    commonality in field data so that it can be combined properly 3.
    How to handle unicode in urls Change list 08/26/2011 Clean-file
    attribute based changes 1. added digitalSignature to objects 2.
    added softwarePackage to objects 3. added taggant to objects 4.
    added numerous elements to fileObject 11/12/2009 1. adding
    documentation across the schema 2. added partner to
    OriginTypeEnum 3. made sha1 in fileObject optional 4. added
    isDamaged as a propertyType 5. changed property name isNon-
    replicating to isNonReplicating 6/11/2009 1. incremented version
    2.Rename parents/children in relationship to source/target 3.
    Add generic relationship, ‘relatedTo’ 4. Make commonality
    element in fieldDataEntry optional 5. Add unknown element to
    origintypeenum 6. Remove ipv4 and ipv6 from locationenum 7. Make
    id on ip object startaddress-endaddress even if startaddress ==
    endaddress. Added IPRange type 8. Add optional firstSeenDate to
    fieldDataEntry, for first time entity providing data saw the
    object 6/4/2009 1. File - id should be a xs:hexBinary 2. File -
    extraHash should be a xs:string 3. Uri – add optional
    ipProtocol field, with enumeration of values tcp/udp/icmp etc.
    4. Uri – add documentation that protocol in uri needs to be
    either from well known list (from iana.org) or ‘unknown’ 5.
    Domain - need to fix documentation for domain – example is
    wrong 6. registry – remove valuedata – it is in a property
    7. ip object – rename to ip, and give it a start address and
    end address. Share a single address by making start and end the
    same. Id will be address or startaddress-endaddress 8. service
    – delete – subsumed by uri with extra data elements in it 9.
    classification – remove modifiers (attributes) on category and
    put in properties 10. classification – add documentation that
    category is companyname:category 11. objectProperty – move
    timestamp to be top level instead of on each property and make
    it required 12. relationship – make timestamp required 13.
    relationship – add doc on runs. removed 'exploits' - it refers
    to environment object that no longer exists 14. added comment
    field to propertyenum 15. made timeStamp -> timestamp for
    consistency 16.incremented version 5/31/2009 1. incremented
    version 2. changed url to uri 3. removed environment object and
    related enumerations 4. added restriction on uri to not allow a
    question mark (?) 5/15/2009 1. incremented version 2. Added
    neutral classification type 3. Added numberOfWebsitesHosting and
    numberOfWebsitesRedirecting to volume units enumeration 4. added
    referrer, operatingSystem, userAgent and browser to properties
    5. made classification type attribute required 5/8/2009 1. added
    new object type for asn 2. moved domain information to
    properties, so that domains info can be timestamped 3. added
    properties for geolocation of an ip address 4. added property
    for location url for a file 5. added VolumeUnitsEnum and volume
    tag in fieldData. This is to allow sharing of actual prevalence
    numbers, with various units. 6. Added ipProtocol (tcp/udp) to
    service object. Also changed names of expectedProtocol and
    actualProtocol to be expectedApplicationProtocol and
    actualApplicationProtocol 7. added 'references' surrounding tag
    to ref tag in fieldDataEntry and objectProperty, so that can
    assign multiple references if required 8. made id on file back
    to hexBinary. Use length to figure out what hash it is. 9.
    incremented version 10. added properties for httpMethod and
    postData 11. added relationship types 'contactedBy' and
    'downloadedFrom' 4/17/2009 1. Incremented version 2. Added
    unwanted to ClassificationTypeEnum 3. Added text about ids for
    files to documentation 4. Removed filename from file object
    definition 5. Relaxed requirement on id of file to be an
    xs:hexString to be an xs:string to allow e.g. md5:aaaaabbbbccc
    as an id. Not enormously happy about that… 6. Made sha256
    optional and sha1 required in files 7. Added “open issues”
    section in documentation for top level element 8. Category is
    now an xs:string; deleted CategoryTypeEnum 9. Added comment to
    doc on fieldDataEntry about using standard time periods, but
    kept start date and end date 10. Added objectProperties element,
    and example illustratingProperties.xml. Currently allowed
    properties are filename, filepath, registryValueData and
    urlParameterString. There is an optional timestamp on each
    property. I allowed objectProperty to have an id, so that it can
    be referenced elsewhere, although we might want to re-think
    that. 11. Added some better documentation to relationships 12.
    Added more documentation throughout The version of the schema.
    This is currently fixed to be 1.1. A required identifier for the
    document."""
    subclass = None
    superclass = None
    def __init__(self, version=None, id=None, company=None, author=None, comment=None, timestamp=None, objects=None, objectProperties=None, relationships=None, fieldData=None):
        self.version = _cast(float, version)
        self.id = _cast(None, id)
        self.company = company
        self.author = author
        self.comment = comment
        self.timestamp = timestamp
        self.objects = objects
        self.objectProperties = objectProperties
        self.relationships = relationships
        self.fieldData = fieldData
    def factory(*args_, **kwargs_):
        if malwareMetaData.subclass:
            return malwareMetaData.subclass(*args_, **kwargs_)
        else:
            return malwareMetaData(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_company(self): return self.company
    def set_company(self, company): self.company = company
    def get_author(self): return self.author
    def set_author(self, author): self.author = author
    def get_comment(self): return self.comment
    def set_comment(self, comment): self.comment = comment
    def get_timestamp(self): return self.timestamp
    def set_timestamp(self, timestamp): self.timestamp = timestamp
    def get_objects(self): return self.objects
    def set_objects(self, objects): self.objects = objects
    def get_objectProperties(self): return self.objectProperties
    def set_objectProperties(self, objectProperties): self.objectProperties = objectProperties
    def get_relationships(self): return self.relationships
    def set_relationships(self, relationships): self.relationships = relationships
    def get_fieldData(self): return self.fieldData
    def set_fieldData(self, fieldData): self.fieldData = fieldData
    def get_version(self): return self.version
    def set_version(self, version): self.version = version
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='malwareMetaData', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='malwareMetaData')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='malwareMetaData'):
        if self.version is not None and 'version' not in already_processed:
            already_processed.append('version')
            write(' version="%s"' % self.gds_format_float(self.version, input_name='version'))
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='malwareMetaData', fromsubclass_=False):
        if self.company is not None:
            showIndent(write, level)
            write('<%scompany>%s</%scompany>\n' % (namespace_, quote_xml(self.company), namespace_))
        if self.author is not None:
            showIndent(write, level)
            write('<%sauthor>%s</%sauthor>\n' % (namespace_, quote_xml(self.author), namespace_))
        if self.comment is not None:
            showIndent(write, level)
            write('<%scomment>%s</%scomment>\n' % (namespace_, quote_xml(self.comment), namespace_))
        if self.timestamp is not None:
            showIndent(write, level)
            write('<%stimestamp>%s</%stimestamp>\n' % (namespace_, quote_xml(self.timestamp), namespace_))
        if self.objects is not None:
            self.objects.export(write, level, namespace_, name_='objects')
        if self.objectProperties is not None:
            self.objectProperties.export(write, level, namespace_, name_='objectProperties')
        if self.relationships is not None:
            self.relationships.export(write, level, namespace_, name_='relationships')
        if self.fieldData is not None:
            self.fieldData.export(write, level, namespace_, name_='fieldData')
    def hasContent_(self):
        if (
            self.company is not None or
            self.author is not None or
            self.comment is not None or
            self.timestamp is not None or
            self.objects is not None or
            self.objectProperties is not None or
            self.relationships is not None or
            self.fieldData is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('version', node)
        if value is not None and 'version' not in already_processed:
            already_processed.append('version')
            try:
                self.version = float(value)
            except ValueError, exp:
                raise ValueError('Bad float/double attribute (version): %s' % exp)
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'company':
            company_ = child_.text
            company_ = self.gds_validate_string(company_, node, 'company')
            self.company = company_
        elif nodeName_ == 'author':
            author_ = child_.text
            author_ = self.gds_validate_string(author_, node, 'author')
            self.author = author_
        elif nodeName_ == 'comment':
            comment_ = child_.text
            comment_ = self.gds_validate_string(comment_, node, 'comment')
            self.comment = comment_
        elif nodeName_ == 'timestamp':
            timestamp_ = child_.text
            timestamp_ = self.gds_validate_string(timestamp_, node, 'timestamp')
            self.timestamp = timestamp_
        elif nodeName_ == 'objects':
            obj_ = objects.factory()
            obj_.build(child_)
            self.set_objects(obj_)
        elif nodeName_ == 'objectProperties':
            obj_ = objectProperties.factory()
            obj_.build(child_)
            self.set_objectProperties(obj_)
        elif nodeName_ == 'relationships':
            obj_ = relationships.factory()
            obj_.build(child_)
            self.set_relationships(obj_)
        elif nodeName_ == 'fieldData':
            obj_ = fieldData.factory()
            obj_.build(child_)
            self.set_fieldData(obj_)
# end class malwareMetaData


class objects(GeneratedsSuper):
    """Objects are globally unique files, urls, domain, registry, ipAddress
    etc. The data within the object is supporting data for the
    globally unique object. For example, files have an id (by
    convention the hash, sha256 if available, else weaker ones), and
    the data for the file is the hashes, sizes etc. Urls have an id
    (the url itself), and data which is simply the url parts broken
    out. There are no dates, etc in the objects. These are first
    class, global objects."""
    subclass = None
    superclass = None
    def __init__(self, file=None, uri=None, domain=None, registry=None, ip=None, asn=None, entity=None, classification=None, softwarePackage=None, digitalSignature=None, taggant=None):
        if file is None:
            self.file = []
        else:
            self.file = file
        if uri is None:
            self.uri = []
        else:
            self.uri = uri
        if domain is None:
            self.domain = []
        else:
            self.domain = domain
        if registry is None:
            self.registry = []
        else:
            self.registry = registry
        if ip is None:
            self.ip = []
        else:
            self.ip = ip
        if asn is None:
            self.asn = []
        else:
            self.asn = asn
        if entity is None:
            self.entity = []
        else:
            self.entity = entity
        if classification is None:
            self.classification = []
        else:
            self.classification = classification
        if softwarePackage is None:
            self.softwarePackage = []
        else:
            self.softwarePackage = softwarePackage
        if digitalSignature is None:
            self.digitalSignature = []
        else:
            self.digitalSignature = digitalSignature
        if taggant is None:
            self.taggant = []
        else:
            self.taggant = taggant
    def factory(*args_, **kwargs_):
        if objects.subclass:
            return objects.subclass(*args_, **kwargs_)
        else:
            return objects(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_file(self): return self.file
    def set_file(self, file): self.file = file
    def add_file(self, value): self.file.append(value)
    def insert_file(self, index, value): self.file[index] = value
    def get_uri(self): return self.uri
    def set_uri(self, uri): self.uri = uri
    def add_uri(self, value): self.uri.append(value)
    def insert_uri(self, index, value): self.uri[index] = value
    def get_domain(self): return self.domain
    def set_domain(self, domain): self.domain = domain
    def add_domain(self, value): self.domain.append(value)
    def insert_domain(self, index, value): self.domain[index] = value
    def get_registry(self): return self.registry
    def set_registry(self, registry): self.registry = registry
    def add_registry(self, value): self.registry.append(value)
    def insert_registry(self, index, value): self.registry[index] = value
    def get_ip(self): return self.ip
    def set_ip(self, ip): self.ip = ip
    def add_ip(self, value): self.ip.append(value)
    def insert_ip(self, index, value): self.ip[index] = value
    def get_asn(self): return self.asn
    def set_asn(self, asn): self.asn = asn
    def add_asn(self, value): self.asn.append(value)
    def insert_asn(self, index, value): self.asn[index] = value
    def get_entity(self): return self.entity
    def set_entity(self, entity): self.entity = entity
    def add_entity(self, value): self.entity.append(value)
    def insert_entity(self, index, value): self.entity[index] = value
    def get_classification(self): return self.classification
    def set_classification(self, classification): self.classification = classification
    def add_classification(self, value): self.classification.append(value)
    def insert_classification(self, index, value): self.classification[index] = value
    def get_softwarePackage(self): return self.softwarePackage
    def set_softwarePackage(self, softwarePackage): self.softwarePackage = softwarePackage
    def add_softwarePackage(self, value): self.softwarePackage.append(value)
    def insert_softwarePackage(self, index, value): self.softwarePackage[index] = value
    def get_digitalSignature(self): return self.digitalSignature
    def set_digitalSignature(self, digitalSignature): self.digitalSignature = digitalSignature
    def add_digitalSignature(self, value): self.digitalSignature.append(value)
    def insert_digitalSignature(self, index, value): self.digitalSignature[index] = value
    def get_taggant(self): return self.taggant
    def set_taggant(self, taggant): self.taggant = taggant
    def add_taggant(self, value): self.taggant.append(value)
    def insert_taggant(self, index, value): self.taggant[index] = value
    def export(self, write, level, namespace_='', name_='objects', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='objects')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='objects'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='objects', fromsubclass_=False):
        for file_ in self.file:
            file_.export(write, level, namespace_, name_='file')
        for uri_ in self.uri:
            uri_.export(write, level, namespace_, name_='uri')
        for domain_ in self.domain:
            domain_.export(write, level, namespace_, name_='domain')
        for registry_ in self.registry:
            registry_.export(write, level, namespace_, name_='registry')
        for ip_ in self.ip:
            ip_.export(write, level, namespace_, name_='ip')
        for asn_ in self.asn:
            asn_.export(write, level, namespace_, name_='asn')
        for entity_ in self.entity:
            entity_.export(write, level, namespace_, name_='entity')
        for classification_ in self.classification:
            classification_.export(write, level, namespace_, name_='classification')
        for softwarePackage_ in self.softwarePackage:
            softwarePackage_.export(write, level, namespace_, name_='softwarePackage')
        for digitalSignature_ in self.digitalSignature:
            digitalSignature_.export(write, level, namespace_, name_='digitalSignature')
        for taggant_ in self.taggant:
            taggant_.export(write, level, namespace_, name_='taggant')
    def hasContent_(self):
        if (
            self.file or
            self.uri or
            self.domain or
            self.registry or
            self.ip or
            self.asn or
            self.entity or
            self.classification or
            self.softwarePackage or
            self.digitalSignature or
            self.taggant
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'file':
            obj_ = fileObject.factory()
            obj_.build(child_)
            self.file.append(obj_)
        elif nodeName_ == 'uri':
            obj_ = uriObject.factory()
            obj_.build(child_)
            self.uri.append(obj_)
        elif nodeName_ == 'domain':
            obj_ = domainObject.factory()
            obj_.build(child_)
            self.domain.append(obj_)
        elif nodeName_ == 'registry':
            obj_ = registryObject.factory()
            obj_.build(child_)
            self.registry.append(obj_)
        elif nodeName_ == 'ip':
            obj_ = IPObject.factory()
            obj_.build(child_)
            self.ip.append(obj_)
        elif nodeName_ == 'asn':
            obj_ = ASNObject.factory()
            obj_.build(child_)
            self.asn.append(obj_)
        elif nodeName_ == 'entity':
            obj_ = entityObject.factory()
            obj_.build(child_)
            self.entity.append(obj_)
        elif nodeName_ == 'classification':
            obj_ = classificationObject.factory()
            obj_.build(child_)
            self.classification.append(obj_)
        elif nodeName_ == 'softwarePackage':
            obj_ = softwarePackageObject.factory()
            obj_.build(child_)
            self.softwarePackage.append(obj_)
        elif nodeName_ == 'digitalSignature':
            obj_ = digitalSignatureObject.factory()
            obj_.build(child_)
            self.digitalSignature.append(obj_)
        elif nodeName_ == 'taggant':
            obj_ = taggantObject.factory()
            obj_.build(child_)
            self.taggant.append(obj_)
# end class objects


class objectProperties(GeneratedsSuper):
    """Properties of objects that do not make sense as relationships. e.g.
    file names, url parameter strings, registry value data."""
    subclass = None
    superclass = None
    def __init__(self, objectProperty=None):
        if objectProperty is None:
            self.objectProperty = []
        else:
            self.objectProperty = objectProperty
    def factory(*args_, **kwargs_):
        if objectProperties.subclass:
            return objectProperties.subclass(*args_, **kwargs_)
        else:
            return objectProperties(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_objectProperty(self): return self.objectProperty
    def set_objectProperty(self, objectProperty): self.objectProperty = objectProperty
    def add_objectProperty(self, value): self.objectProperty.append(value)
    def insert_objectProperty(self, index, value): self.objectProperty[index] = value
    def export(self, write, level, namespace_='', name_='objectProperties', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='objectProperties')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='objectProperties'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='objectProperties', fromsubclass_=False):
        for objectProperty_ in self.objectProperty:
            objectProperty_.export(write, level, namespace_, name_='objectProperty')
    def hasContent_(self):
        if (
            self.objectProperty
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'objectProperty':
            obj_ = objectProperty.factory()
            obj_.build(child_)
            self.objectProperty.append(obj_)
# end class objectProperties


class relationships(GeneratedsSuper):
    """Relationships between objects."""
    subclass = None
    superclass = None
    def __init__(self, relationship=None):
        if relationship is None:
            self.relationship = []
        else:
            self.relationship = relationship
    def factory(*args_, **kwargs_):
        if relationships.subclass:
            return relationships.subclass(*args_, **kwargs_)
        else:
            return relationships(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_relationship(self): return self.relationship
    def set_relationship(self, relationship): self.relationship = relationship
    def add_relationship(self, value): self.relationship.append(value)
    def insert_relationship(self, index, value): self.relationship[index] = value
    def export(self, write, level, namespace_='', name_='relationships', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='relationships')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='relationships'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='relationships', fromsubclass_=False):
        for relationship_ in self.relationship:
            relationship_.export(write, level, namespace_, name_='relationship')
    def hasContent_(self):
        if (
            self.relationship
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'relationship':
            obj_ = relationship.factory()
            obj_.build(child_)
            self.relationship.append(obj_)
# end class relationships


class fieldData(GeneratedsSuper):
    """Prevalence data."""
    subclass = None
    superclass = None
    def __init__(self, fieldDataEntry=None):
        if fieldDataEntry is None:
            self.fieldDataEntry = []
        else:
            self.fieldDataEntry = fieldDataEntry
    def factory(*args_, **kwargs_):
        if fieldData.subclass:
            return fieldData.subclass(*args_, **kwargs_)
        else:
            return fieldData(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_fieldDataEntry(self): return self.fieldDataEntry
    def set_fieldDataEntry(self, fieldDataEntry): self.fieldDataEntry = fieldDataEntry
    def add_fieldDataEntry(self, value): self.fieldDataEntry.append(value)
    def insert_fieldDataEntry(self, index, value): self.fieldDataEntry[index] = value
    def export(self, write, level, namespace_='', name_='fieldData', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='fieldData')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='fieldData'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='fieldData', fromsubclass_=False):
        for fieldDataEntry_ in self.fieldDataEntry:
            fieldDataEntry_.export(write, level, namespace_, name_='fieldDataEntry')
    def hasContent_(self):
        if (
            self.fieldDataEntry
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'fieldDataEntry':
            obj_ = fieldDataEntry.factory()
            obj_.build(child_)
            self.fieldDataEntry.append(obj_)
# end class fieldData


class fileObject(GeneratedsSuper):
    """Object definition for files. The required attribute is the id, which
    needs to be globally unique. By convention, the value used is a
    hash, the stronger the better. The choice should be: use sha256
    if you have it, if not use sha1, if not use md5. Other hashes
    and file sizes are recorded in the elements. File names are put
    in as properties."""
    subclass = None
    superclass = None
    def __init__(self, id=None, md5=None, sha1=None, sha256=None, sha512=None, size=None, crc32=None, fileType=None, extraHash=None, filename=None, normalizedNativePath=None, filenameWithinInstaller=None, folderWithinInstaller=None, vendor=None, internalName=None, language=None, productName=None, fileVersion=None, productVersion=None, developmentEnvironment=None, checksum=None, architecture=None, buildTimeDateStamp=None, compilerVersion=None, linkerVersion=None, minOSVersionCPE=None, numberOfSections=None, MIMEType=None, requiredPrivilege=None, digitalSignature=None, taggant=None):
        self.id = _cast(None, id)
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.sha512 = sha512
        self.size = size
        self.crc32 = crc32
        if fileType is None:
            self.fileType = []
        else:
            self.fileType = fileType
        if extraHash is None:
            self.extraHash = []
        else:
            self.extraHash = extraHash
        if filename is None:
            self.filename = []
        else:
            self.filename = filename
        if normalizedNativePath is None:
            self.normalizedNativePath = []
        else:
            self.normalizedNativePath = normalizedNativePath
        if filenameWithinInstaller is None:
            self.filenameWithinInstaller = []
        else:
            self.filenameWithinInstaller = filenameWithinInstaller
        if folderWithinInstaller is None:
            self.folderWithinInstaller = []
        else:
            self.folderWithinInstaller = folderWithinInstaller
        self.vendor = vendor
        if internalName is None:
            self.internalName = []
        else:
            self.internalName = internalName
        if language is None:
            self.language = []
        else:
            self.language = language
        self.productName = productName
        self.fileVersion = fileVersion
        self.productVersion = productVersion
        self.developmentEnvironment = developmentEnvironment
        self.checksum = checksum
        self.architecture = architecture
        self.buildTimeDateStamp = buildTimeDateStamp
        self.compilerVersion = compilerVersion
        self.linkerVersion = linkerVersion
        self.minOSVersionCPE = minOSVersionCPE
        self.numberOfSections = numberOfSections
        self.MIMEType = MIMEType
        self.requiredPrivilege = requiredPrivilege
        self.digitalSignature = digitalSignature
        self.taggant = taggant
    def factory(*args_, **kwargs_):
        if fileObject.subclass:
            return fileObject.subclass(*args_, **kwargs_)
        else:
            return fileObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_md5(self): return self.md5
    def set_md5(self, md5): self.md5 = md5
    def get_sha1(self): return self.sha1
    def set_sha1(self, sha1): self.sha1 = sha1
    def get_sha256(self): return self.sha256
    def set_sha256(self, sha256): self.sha256 = sha256
    def get_sha512(self): return self.sha512
    def set_sha512(self, sha512): self.sha512 = sha512
    def get_size(self): return self.size
    def set_size(self, size): self.size = size
    def get_crc32(self): return self.crc32
    def set_crc32(self, crc32): self.crc32 = crc32
    def get_fileType(self): return self.fileType
    def set_fileType(self, fileType): self.fileType = fileType
    def add_fileType(self, value): self.fileType.append(value)
    def insert_fileType(self, index, value): self.fileType[index] = value
    def get_extraHash(self): return self.extraHash
    def set_extraHash(self, extraHash): self.extraHash = extraHash
    def add_extraHash(self, value): self.extraHash.append(value)
    def insert_extraHash(self, index, value): self.extraHash[index] = value
    def get_filename(self): return self.filename
    def set_filename(self, filename): self.filename = filename
    def add_filename(self, value): self.filename.append(value)
    def insert_filename(self, index, value): self.filename[index] = value
    def get_normalizedNativePath(self): return self.normalizedNativePath
    def set_normalizedNativePath(self, normalizedNativePath): self.normalizedNativePath = normalizedNativePath
    def add_normalizedNativePath(self, value): self.normalizedNativePath.append(value)
    def insert_normalizedNativePath(self, index, value): self.normalizedNativePath[index] = value
    def get_filenameWithinInstaller(self): return self.filenameWithinInstaller
    def set_filenameWithinInstaller(self, filenameWithinInstaller): self.filenameWithinInstaller = filenameWithinInstaller
    def add_filenameWithinInstaller(self, value): self.filenameWithinInstaller.append(value)
    def insert_filenameWithinInstaller(self, index, value): self.filenameWithinInstaller[index] = value
    def get_folderWithinInstaller(self): return self.folderWithinInstaller
    def set_folderWithinInstaller(self, folderWithinInstaller): self.folderWithinInstaller = folderWithinInstaller
    def add_folderWithinInstaller(self, value): self.folderWithinInstaller.append(value)
    def insert_folderWithinInstaller(self, index, value): self.folderWithinInstaller[index] = value
    def get_vendor(self): return self.vendor
    def set_vendor(self, vendor): self.vendor = vendor
    def get_internalName(self): return self.internalName
    def set_internalName(self, internalName): self.internalName = internalName
    def add_internalName(self, value): self.internalName.append(value)
    def insert_internalName(self, index, value): self.internalName[index] = value
    def get_language(self): return self.language
    def set_language(self, language): self.language = language
    def add_language(self, value): self.language.append(value)
    def insert_language(self, index, value): self.language[index] = value
    def get_productName(self): return self.productName
    def set_productName(self, productName): self.productName = productName
    def get_fileVersion(self): return self.fileVersion
    def set_fileVersion(self, fileVersion): self.fileVersion = fileVersion
    def get_productVersion(self): return self.productVersion
    def set_productVersion(self, productVersion): self.productVersion = productVersion
    def get_developmentEnvironment(self): return self.developmentEnvironment
    def set_developmentEnvironment(self, developmentEnvironment): self.developmentEnvironment = developmentEnvironment
    def get_checksum(self): return self.checksum
    def set_checksum(self, checksum): self.checksum = checksum
    def get_architecture(self): return self.architecture
    def set_architecture(self, architecture): self.architecture = architecture
    def get_buildTimeDateStamp(self): return self.buildTimeDateStamp
    def set_buildTimeDateStamp(self, buildTimeDateStamp): self.buildTimeDateStamp = buildTimeDateStamp
    def get_compilerVersion(self): return self.compilerVersion
    def set_compilerVersion(self, compilerVersion): self.compilerVersion = compilerVersion
    def get_linkerVersion(self): return self.linkerVersion
    def set_linkerVersion(self, linkerVersion): self.linkerVersion = linkerVersion
    def get_minOSVersionCPE(self): return self.minOSVersionCPE
    def set_minOSVersionCPE(self, minOSVersionCPE): self.minOSVersionCPE = minOSVersionCPE
    def get_numberOfSections(self): return self.numberOfSections
    def set_numberOfSections(self, numberOfSections): self.numberOfSections = numberOfSections
    def get_MIMEType(self): return self.MIMEType
    def set_MIMEType(self, MIMEType): self.MIMEType = MIMEType
    def get_requiredPrivilege(self): return self.requiredPrivilege
    def set_requiredPrivilege(self, requiredPrivilege): self.requiredPrivilege = requiredPrivilege
    def get_digitalSignature(self): return self.digitalSignature
    def set_digitalSignature(self, digitalSignature): self.digitalSignature = digitalSignature
    def get_taggant(self): return self.taggant
    def set_taggant(self, taggant): self.taggant = taggant
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='fileObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='fileObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='fileObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='', name_='fileObject', fromsubclass_=False):
        if self.md5 is not None:
            self.md5.export(write, level, namespace_, name_='md5', )
        if self.sha1 is not None:
            self.sha1.export(write, level, namespace_, name_='sha1')
        if self.sha256 is not None:
            self.sha256.export(write, level, namespace_, name_='sha256')
        if self.sha512 is not None:
            self.sha512.export(write, level, namespace_, name_='sha512')
        if self.size is not None:
            showIndent(write, level)
            write('<%ssize>%s</%ssize>\n' % (namespace_, self.gds_format_integer(self.size, input_name='size'), namespace_))
        if self.crc32 is not None:
            showIndent(write, level)
            write('<%scrc32>%s</%scrc32>\n' % (namespace_, quote_xml(self.crc32), namespace_))
        for fileType_ in self.fileType:
            showIndent(write, level)
            write('<%sfileType>%s</%sfileType>\n' % (namespace_, quote_xml(fileType_), namespace_))
        for extraHash_ in self.extraHash:
            extraHash_.export(write, level, namespace_, name_='extraHash')
        for filename_ in self.filename:
            showIndent(write, level)
            write('<%sfilename>%s</%sfilename>\n' % (namespace_, quote_xml(filename_), namespace_))
        for normalizedNativePath_ in self.normalizedNativePath:
            showIndent(write, level)
            write('<%snormalizedNativePath>%s</%snormalizedNativePath>\n' % (namespace_, quote_xml(normalizedNativePath_), namespace_))
        for filenameWithinInstaller_ in self.filenameWithinInstaller:
            showIndent(write, level)
            write('<%sfilenameWithinInstaller>%s</%sfilenameWithinInstaller>\n' % (namespace_, quote_xml(filenameWithinInstaller_), namespace_))
        for folderWithinInstaller_ in self.folderWithinInstaller:
            showIndent(write, level)
            write('<%sfolderWithinInstaller>%s</%sfolderWithinInstaller>\n' % (namespace_, quote_xml(folderWithinInstaller_), namespace_))
        if self.vendor is not None:
            showIndent(write, level)
            write('<%svendor>%s</%svendor>\n' % (namespace_, quote_xml(self.vendor), namespace_))
        for internalName_ in self.internalName:
            showIndent(write, level)
            write('<%sinternalName>%s</%sinternalName>\n' % (namespace_, quote_xml(internalName_), namespace_))
        for language_ in self.language:
            showIndent(write, level)
            write('<%slanguage>%s</%slanguage>\n' % (namespace_, quote_xml(language_), namespace_))
        if self.productName is not None:
            showIndent(write, level)
            write('<%sproductName>%s</%sproductName>\n' % (namespace_, quote_xml(self.productName), namespace_))
        if self.fileVersion is not None:
            showIndent(write, level)
            write('<%sfileVersion>%s</%sfileVersion>\n' % (namespace_, quote_xml(self.fileVersion), namespace_))
        if self.productVersion is not None:
            showIndent(write, level)
            write('<%sproductVersion>%s</%sproductVersion>\n' % (namespace_, quote_xml(self.productVersion), namespace_))
        if self.developmentEnvironment is not None:
            showIndent(write, level)
            write('<%sdevelopmentEnvironment>%s</%sdevelopmentEnvironment>\n' % (namespace_, quote_xml(self.developmentEnvironment), namespace_))
        if self.checksum is not None:
            self.checksum.export(write, level, namespace_, name_='checksum')
        if self.architecture is not None:
            showIndent(write, level)
            write('<%sarchitecture>%s</%sarchitecture>\n' % (namespace_, quote_xml(self.architecture), namespace_))
        if self.buildTimeDateStamp is not None:
            showIndent(write, level)
            write('<%sbuildTimeDateStamp>%s</%sbuildTimeDateStamp>\n' % (namespace_, quote_xml(self.buildTimeDateStamp), namespace_))
        if self.compilerVersion is not None:
            showIndent(write, level)
            write('<%scompilerVersion>%s</%scompilerVersion>\n' % (namespace_, quote_xml(self.compilerVersion), namespace_))
        if self.linkerVersion is not None:
            showIndent(write, level)
            write('<%slinkerVersion>%s</%slinkerVersion>\n' % (namespace_, self.gds_format_float(self.linkerVersion, input_name='linkerVersion'), namespace_))
        if self.minOSVersionCPE is not None:
            showIndent(write, level)
            write('<%sminOSVersionCPE>%s</%sminOSVersionCPE>\n' % (namespace_, quote_xml(self.minOSVersionCPE), namespace_))
        if self.numberOfSections is not None:
            showIndent(write, level)
            write('<%snumberOfSections>%s</%snumberOfSections>\n' % (namespace_, self.gds_format_integer(self.numberOfSections, input_name='numberOfSections'), namespace_))
        if self.MIMEType is not None:
            showIndent(write, level)
            write('<%sMIMEType>%s</%sMIMEType>\n' % (namespace_, quote_xml(self.MIMEType), namespace_))
        if self.requiredPrivilege is not None:
            showIndent(write, level)
            write('<%srequiredPrivilege>%s</%srequiredPrivilege>\n' % (namespace_, quote_xml(self.requiredPrivilege), namespace_))
        if self.digitalSignature is not None:
            self.digitalSignature.export(write, level, namespace_, name_='digitalSignature')
        if self.taggant is not None:
            self.taggant.export(write, level, namespace_, name_='taggant')
    def hasContent_(self):
        if (
            self.md5 is not None or
            self.sha1 is not None or
            self.sha256 is not None or
            self.sha512 is not None or
            self.size is not None or
            self.crc32 is not None or
            self.fileType or
            self.extraHash or
            self.filename or
            self.normalizedNativePath or
            self.filenameWithinInstaller or
            self.folderWithinInstaller or
            self.vendor is not None or
            self.internalName or
            self.language or
            self.productName is not None or
            self.fileVersion is not None or
            self.productVersion is not None or
            self.developmentEnvironment is not None or
            self.checksum is not None or
            self.architecture is not None or
            self.buildTimeDateStamp is not None or
            self.compilerVersion is not None or
            self.linkerVersion is not None or
            self.minOSVersionCPE is not None or
            self.numberOfSections is not None or
            self.MIMEType is not None or
            self.requiredPrivilege is not None or
            self.digitalSignature is not None or
            self.taggant is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'md5':
            obj_ = xs_hexBinary.factory()
            obj_.build(child_)
            self.set_md5(obj_)
        elif nodeName_ == 'sha1':
            obj_ = xs_hexBinary.factory()
            obj_.build(child_)
            self.set_sha1(obj_)
        elif nodeName_ == 'sha256':
            obj_ = xs_hexBinary.factory()
            obj_.build(child_)
            self.set_sha256(obj_)
        elif nodeName_ == 'sha512':
            obj_ = xs_hexBinary.factory()
            obj_.build(child_)
            self.set_sha512(obj_)
        elif nodeName_ == 'size':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'size')
            self.size = ival_
        elif nodeName_ == 'crc32':
            crc32_ = child_.text
            crc32_ = self.gds_validate_string(crc32_, node, 'crc32')
            self.crc32 = crc32_
        elif nodeName_ == 'fileType':
            fileType_ = child_.text
            fileType_ = self.gds_validate_string(fileType_, node, 'fileType')
            self.fileType.append(fileType_)
        elif nodeName_ == 'extraHash':
            obj_ = extraHash.factory()
            obj_.build(child_)
            self.extraHash.append(obj_)
        elif nodeName_ == 'filename':
            filename_ = child_.text
            filename_ = self.gds_validate_string(filename_, node, 'filename')
            self.filename.append(filename_)
        elif nodeName_ == 'normalizedNativePath':
            normalizedNativePath_ = child_.text
            normalizedNativePath_ = self.gds_validate_string(normalizedNativePath_, node, 'normalizedNativePath')
            self.normalizedNativePath.append(normalizedNativePath_)
        elif nodeName_ == 'filenameWithinInstaller':
            filenameWithinInstaller_ = child_.text
            filenameWithinInstaller_ = self.gds_validate_string(filenameWithinInstaller_, node, 'filenameWithinInstaller')
            self.filenameWithinInstaller.append(filenameWithinInstaller_)
        elif nodeName_ == 'folderWithinInstaller':
            folderWithinInstaller_ = child_.text
            folderWithinInstaller_ = self.gds_validate_string(folderWithinInstaller_, node, 'folderWithinInstaller')
            self.folderWithinInstaller.append(folderWithinInstaller_)
        elif nodeName_ == 'vendor':
            vendor_ = child_.text
            vendor_ = self.gds_validate_string(vendor_, node, 'vendor')
            self.vendor = vendor_
        elif nodeName_ == 'internalName':
            internalName_ = child_.text
            internalName_ = self.gds_validate_string(internalName_, node, 'internalName')
            self.internalName.append(internalName_)
        elif nodeName_ == 'language':
            language_ = child_.text
            language_ = self.gds_validate_string(language_, node, 'language')
            self.language.append(language_)
        elif nodeName_ == 'productName':
            productName_ = child_.text
            productName_ = self.gds_validate_string(productName_, node, 'productName')
            self.productName = productName_
        elif nodeName_ == 'fileVersion':
            fileVersion_ = child_.text
            fileVersion_ = self.gds_validate_string(fileVersion_, node, 'fileVersion')
            self.fileVersion = fileVersion_
        elif nodeName_ == 'productVersion':
            productVersion_ = child_.text
            productVersion_ = self.gds_validate_string(productVersion_, node, 'productVersion')
            self.productVersion = productVersion_
        elif nodeName_ == 'developmentEnvironment':
            developmentEnvironment_ = child_.text
            developmentEnvironment_ = self.gds_validate_string(developmentEnvironment_, node, 'developmentEnvironment')
            self.developmentEnvironment = developmentEnvironment_
        elif nodeName_ == 'checksum':
            obj_ = xs_hexBinary.factory()
            obj_.build(child_)
            self.set_checksum(obj_)
        elif nodeName_ == 'architecture':
            architecture_ = child_.text
            architecture_ = self.gds_validate_string(architecture_, node, 'architecture')
            self.architecture = architecture_
        elif nodeName_ == 'buildTimeDateStamp':
            buildTimeDateStamp_ = child_.text
            buildTimeDateStamp_ = self.gds_validate_string(buildTimeDateStamp_, node, 'buildTimeDateStamp')
            self.buildTimeDateStamp = buildTimeDateStamp_
        elif nodeName_ == 'compilerVersion':
            compilerVersion_ = child_.text
            compilerVersion_ = self.gds_validate_string(compilerVersion_, node, 'compilerVersion')
            self.compilerVersion = compilerVersion_
        elif nodeName_ == 'linkerVersion':
            sval_ = child_.text
            try:
                fval_ = float(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires float or double: %s' % exp)
            fval_ = self.gds_validate_float(fval_, node, 'linkerVersion')
            self.linkerVersion = fval_
        elif nodeName_ == 'minOSVersionCPE':
            minOSVersionCPE_ = child_.text
            minOSVersionCPE_ = self.gds_validate_string(minOSVersionCPE_, node, 'minOSVersionCPE')
            self.minOSVersionCPE = minOSVersionCPE_
        elif nodeName_ == 'numberOfSections':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'numberOfSections')
            self.numberOfSections = ival_
        elif nodeName_ == 'MIMEType':
            MIMEType_ = child_.text
            MIMEType_ = self.gds_validate_string(MIMEType_, node, 'MIMEType')
            self.MIMEType = MIMEType_
        elif nodeName_ == 'requiredPrivilege':
            requiredPrivilege_ = child_.text
            requiredPrivilege_ = self.gds_validate_string(requiredPrivilege_, node, 'requiredPrivilege')
            self.requiredPrivilege = requiredPrivilege_
        elif nodeName_ == 'digitalSignature':
            obj_ = digitalSignatureObject.factory()
            obj_.build(child_)
            self.set_digitalSignature(obj_)
        elif nodeName_ == 'taggant':
            obj_ = taggantObject.factory()
            obj_.build(child_)
            self.set_taggant(obj_)
# end class fileObject


class extraHash(GeneratedsSuper):
    """Element for inserting fuzzy hashes for example pehash, ssdeep. These
    are put in with this element, with a required attribute 'type'
    used to hold the type of hash."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, valueOf_=None):
        self.type_ = _cast(None, type_)
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if extraHash.subclass:
            return extraHash.subclass(*args_, **kwargs_)
        else:
            return extraHash(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='extraHash', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='extraHash')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='extraHash'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.append('type_')
            write(' type=%s' % (quote_attrib(self.type_)))
    def exportChildren(self, write, level, namespace_='', name_='extraHash', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.append('type')
            self.type_ = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class extraHash


class registryObject(GeneratedsSuper):
    """Registry object. The required attribute is 'id', which is taken to
    be key\\valueName. Keys end in a \, value names start with a \,
    so you have e.g. key =
    hklm\software\microsoft\currentversion\windows\run\ value =\foo
    making the id
    hklm\software\microsoft\currentversion\windows\run\\foo"""
    subclass = None
    superclass = None
    def __init__(self, id=None, key=None, valueName=None):
        self.id = _cast(None, id)
        self.key = key
        self.valueName = valueName
    def factory(*args_, **kwargs_):
        if registryObject.subclass:
            return registryObject.subclass(*args_, **kwargs_)
        else:
            return registryObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_key(self): return self.key
    def set_key(self, key): self.key = key
    def get_valueName(self): return self.valueName
    def set_valueName(self, valueName): self.valueName = valueName
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='registryObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='registryObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='registryObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='registryObject', fromsubclass_=False):
        if self.key is not None:
            showIndent(write, level)
            write('<%skey>%s</%skey>\n' % (namespace_, quote_xml(self.key), namespace_))
        if self.valueName is not None:
            showIndent(write, level)
            write('<%svalueName>%s</%svalueName>\n' % (namespace_, quote_xml(self.valueName), namespace_))
    def hasContent_(self):
        if (
            self.key is not None or
            self.valueName is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'key':
            key_ = child_.text
            key_ = self.gds_validate_string(key_, node, 'key')
            self.key = key_
        elif nodeName_ == 'valueName':
            valueName_ = child_.text
            valueName_ = self.gds_validate_string(valueName_, node, 'valueName')
            self.valueName = valueName_
# end class registryObject


class entityObject(GeneratedsSuper):
    """Entity Object. This is used to record groups, companies etc., and
    departments within organizations. The globally unique id
    (attribute) should be constructed from the company and
    department name, e.g. "Company name:Department name",
    "Mcafee:AVERT labs", or "Russian Business Network"."""
    subclass = None
    superclass = None
    def __init__(self, id=None, name=None):
        self.id = _cast(None, id)
        self.name = name
    def factory(*args_, **kwargs_):
        if entityObject.subclass:
            return entityObject.subclass(*args_, **kwargs_)
        else:
            return entityObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_name(self): return self.name
    def set_name(self, name): self.name = name
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='entityObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='entityObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='entityObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='entityObject', fromsubclass_=False):
        if self.name is not None:
            showIndent(write, level)
            write('<%sname>%s</%sname>\n' % (namespace_, quote_xml(self.name), namespace_))
    def hasContent_(self):
        if (
            self.name is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'name':
            name_ = child_.text
            name_ = self.gds_validate_string(name_, node, 'name')
            self.name = name_
# end class entityObject


class uriObject(GeneratedsSuper):
    """Uri object. Only required element is uri string itself. There are
    elements for each of the broken out elements. The protocol
    should be take from the list at http://www.iana.org/assignments
    /port-numbers, or if not in that list have the value 'unknown'.
    The ipProtocol should be taken from the list
    http://www.iana.org/assignments/protocol-numbers/. The elements
    correspond to the usual breakdown of a uri into its component
    domain, hostname, path, port etc, as described at
    http://en.wikipedia.org/wiki/Uniform_Resource_Locator."""
    subclass = None
    superclass = None
    def __init__(self, id=None, uriString=None, protocol=None, hostname=None, domain=None, port=None, path=None, ipProtocol=None):
        self.id = _cast(None, id)
        self.uriString = uriString
        self.protocol = protocol
        self.hostname = hostname
        self.domain = domain
        self.port = port
        self.path = path
        self.ipProtocol = ipProtocol
    def factory(*args_, **kwargs_):
        if uriObject.subclass:
            return uriObject.subclass(*args_, **kwargs_)
        else:
            return uriObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_uriString(self): return self.uriString
    def set_uriString(self, uriString): self.uriString = uriString
    def validate_NoQuestionMark(self, value):
        # Validate type NoQuestionMark, a restriction on xs:string.
        pass
    def get_protocol(self): return self.protocol
    def set_protocol(self, protocol): self.protocol = protocol
    def get_hostname(self): return self.hostname
    def set_hostname(self, hostname): self.hostname = hostname
    def get_domain(self): return self.domain
    def set_domain(self, domain): self.domain = domain
    def get_port(self): return self.port
    def set_port(self, port): self.port = port
    def get_path(self): return self.path
    def set_path(self, path): self.path = path
    def get_ipProtocol(self): return self.ipProtocol
    def set_ipProtocol(self, ipProtocol): self.ipProtocol = ipProtocol
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='uriObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='uriObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='uriObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='', name_='uriObject', fromsubclass_=False):
        if self.uriString is not None:
            showIndent(write, level)
            write('<%suriString>%s</%suriString>\n' % (namespace_, quote_xml(self.uriString), namespace_))
        if self.protocol is not None:
            showIndent(write, level)
            write('<%sprotocol>%s</%sprotocol>\n' % (namespace_, quote_xml(self.protocol), namespace_))
        if self.hostname is not None:
            showIndent(write, level)
            write('<%shostname>%s</%shostname>\n' % (namespace_, quote_xml(self.hostname), namespace_))
        if self.domain is not None:
            showIndent(write, level)
            write('<%sdomain>%s</%sdomain>\n' % (namespace_, quote_xml(self.domain), namespace_))
        if self.port is not None:
            showIndent(write, level)
            write('<%sport>%s</%sport>\n' % (namespace_, self.gds_format_integer(self.port, input_name='port'), namespace_))
        if self.path is not None:
            showIndent(write, level)
            write('<%spath>%s</%spath>\n' % (namespace_, quote_xml(self.path), namespace_))
        if self.ipProtocol is not None:
            showIndent(write, level)
            write('<%sipProtocol>%s</%sipProtocol>\n' % (namespace_, quote_xml(self.ipProtocol), namespace_))
    def hasContent_(self):
        if (
            self.uriString is not None or
            self.protocol is not None or
            self.hostname is not None or
            self.domain is not None or
            self.port is not None or
            self.path is not None or
            self.ipProtocol is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
            self.validate_NoQuestionMark(self.id)    # validate type NoQuestionMark
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'uriString':
            uriString_ = child_.text
            uriString_ = self.gds_validate_string(uriString_, node, 'uriString')
            self.uriString = uriString_
            self.validate_NoQuestionMark(self.uriString)    # validate type NoQuestionMark
        elif nodeName_ == 'protocol':
            protocol_ = child_.text
            protocol_ = self.gds_validate_string(protocol_, node, 'protocol')
            self.protocol = protocol_
        elif nodeName_ == 'hostname':
            hostname_ = child_.text
            hostname_ = self.gds_validate_string(hostname_, node, 'hostname')
            self.hostname = hostname_
        elif nodeName_ == 'domain':
            domain_ = child_.text
            domain_ = self.gds_validate_string(domain_, node, 'domain')
            self.domain = domain_
        elif nodeName_ == 'port':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'port')
            self.port = ival_
        elif nodeName_ == 'path':
            path_ = child_.text
            path_ = self.gds_validate_string(path_, node, 'path')
            self.path = path_
        elif nodeName_ == 'ipProtocol':
            ipProtocol_ = child_.text
            ipProtocol_ = self.gds_validate_string(ipProtocol_, node, 'ipProtocol')
            self.ipProtocol = ipProtocol_
# end class uriObject


class IPObject(GeneratedsSuper):
    """IP object. Used to hold ipv4, ipv6 ip addresses and address ranges.
    The globally unique id is 'startAddress-endAddress'. There are
    two required elements, startAddress and endAddress, make these
    the same if you are specifying a single address. Thus for ip
    range id, would be e.g. 213.23.45.7-213.23.45.19 For a single
    ip, id would be e.g. 12.34.56.1-12.34.56.1"""
    subclass = None
    superclass = None
    def __init__(self, id=None, startAddress=None, endAddress=None):
        self.id = _cast(None, id)
        self.startAddress = startAddress
        self.endAddress = endAddress
    def factory(*args_, **kwargs_):
        if IPObject.subclass:
            return IPObject.subclass(*args_, **kwargs_)
        else:
            return IPObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_startAddress(self): return self.startAddress
    def set_startAddress(self, startAddress): self.startAddress = startAddress
    def get_endAddress(self): return self.endAddress
    def set_endAddress(self, endAddress): self.endAddress = endAddress
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def validate_IPRange(self, value):
        # Validate type IPRange, a restriction on xs:string.
        pass
    def export(self, write, level, namespace_='', name_='IPObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='IPObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='IPObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='', name_='IPObject', fromsubclass_=False):
        if self.startAddress is not None:
            self.startAddress.export(write, level, namespace_, name_='startAddress', )
        if self.endAddress is not None:
            self.endAddress.export(write, level, namespace_, name_='endAddress', )
    def hasContent_(self):
        if (
            self.startAddress is not None or
            self.endAddress is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
            self.validate_IPRange(self.id)    # validate type IPRange
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'startAddress':
            obj_ = IPAddress.factory()
            obj_.build(child_)
            self.set_startAddress(obj_)
        elif nodeName_ == 'endAddress':
            obj_ = IPAddress.factory()
            obj_.build(child_)
            self.set_endAddress(obj_)
# end class IPObject


class IPAddress(GeneratedsSuper):
    """ip address - string for the actual address and attribute either
    ipv4, ipv6."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, valueOf_=None):
        self.type_ = _cast(None, type_)
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if IPAddress.subclass:
            return IPAddress.subclass(*args_, **kwargs_)
        else:
            return IPAddress(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def validate_IPTypeEnum(self, value):
        # Validate type IPTypeEnum, a restriction on xs:string.
        pass
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='IPAddress', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='IPAddress')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='IPAddress'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.append('type_')
            write(' type=%s' % (quote_attrib(self.type_), ))
    def exportChildren(self, write, level, namespace_='', name_='IPAddress', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.append('type')
            self.type_ = value
            self.validate_IPTypeEnum(self.type_)    # validate type IPTypeEnum
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class IPAddress


class domainObject(GeneratedsSuper):
    """Domain object, used to hold internet domains, e.g.yahoo.com. The
    globally unique identifier (id attribute) is the domain itself.
    whois information on domain is recorded using object properties."""
    subclass = None
    superclass = None
    def __init__(self, id=None, domain=None):
        self.id = _cast(None, id)
        self.domain = domain
    def factory(*args_, **kwargs_):
        if domainObject.subclass:
            return domainObject.subclass(*args_, **kwargs_)
        else:
            return domainObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_domain(self): return self.domain
    def set_domain(self, domain): self.domain = domain
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='domainObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='domainObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='domainObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='domainObject', fromsubclass_=False):
        if self.domain is not None:
            showIndent(write, level)
            write('<%sdomain>%s</%sdomain>\n' % (namespace_, quote_xml(self.domain), namespace_))
    def hasContent_(self):
        if (
            self.domain is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'domain':
            domain_ = child_.text
            domain_ = self.gds_validate_string(domain_, node, 'domain')
            self.domain = domain_
# end class domainObject


class ASNObject(GeneratedsSuper):
    """Object used to hold information on Autonomous System Numbers. An
    autonomous system (AS) is a collection of connected Internet
    Protocol (IP) routing prefixes under the control of one or more
    network operators that presents a common, clearly defined
    routing policy to the Internet. The id is the number, written as
    an integer for both 16 and 32 bit numbers."""
    subclass = None
    superclass = None
    def __init__(self, id=None, as_number=None):
        self.id = _cast(int, id)
        self.as_number = as_number
    def factory(*args_, **kwargs_):
        if ASNObject.subclass:
            return ASNObject.subclass(*args_, **kwargs_)
        else:
            return ASNObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_as_number(self): return self.as_number
    def set_as_number(self, as_number): self.as_number = as_number
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='ASNObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='ASNObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='ASNObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id="%s"' % self.gds_format_integer(self.id, input_name='id'))
    def exportChildren(self, write, level, namespace_='', name_='ASNObject', fromsubclass_=False):
        if self.as_number is not None:
            showIndent(write, level)
            write('<%sas-number>%s</%sas-number>\n' % (namespace_, self.gds_format_integer(self.as_number, input_name='as-number'), namespace_))
    def hasContent_(self):
        if (
            self.as_number is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            try:
                self.id = int(value)
            except ValueError, exp:
                raise_parse_error(node, 'Bad integer attribute: %s' % exp)
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'as-number':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'as_number')
            self.as_number = ival_
# end class ASNObject


class classificationObject(GeneratedsSuper):
    """Classification object, used to hold names or classifications of
    objects. The most common use case for this is detection names
    for files from av scanners. However, this object could be used
    for general classification. The globally unique id (attribute)
    should be created from "Company name:internal classification
    name", e.g. "Mcafee:Generic.DX". The other required attribute is
    the type of classification, e.g. clean, dirty, unknown. There
    are elements to capture the category of the classification. The
    category should be entered in the same way to the classification
    name, e.g. company name:category name, e..g Mcafee:Trojan."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, id=None, classificationName=None, companyName=None, category=None, classificationDetails=None):
        self.type_ = _cast(None, type_)
        self.id = _cast(None, id)
        self.classificationName = classificationName
        self.companyName = companyName
        self.category = category
        self.classificationDetails = classificationDetails
    def factory(*args_, **kwargs_):
        if classificationObject.subclass:
            return classificationObject.subclass(*args_, **kwargs_)
        else:
            return classificationObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_classificationName(self): return self.classificationName
    def set_classificationName(self, classificationName): self.classificationName = classificationName
    def get_companyName(self): return self.companyName
    def set_companyName(self, companyName): self.companyName = companyName
    def get_category(self): return self.category
    def set_category(self, category): self.category = category
    def get_classificationDetails(self): return self.classificationDetails
    def set_classificationDetails(self, classificationDetails): self.classificationDetails = classificationDetails
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def validate_ClassificationTypeEnum(self, value):
        # Validate type ClassificationTypeEnum, a restriction on xs:string.
        pass
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='classificationObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='classificationObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='classificationObject'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.append('type_')
            write(' type=%s' % (quote_attrib(self.type_), ))
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='classificationObject', fromsubclass_=False):
        if self.classificationName is not None:
            showIndent(write, level)
            write('<%sclassificationName>%s</%sclassificationName>\n' % ('mmdef:', quote_xml(self.classificationName), 'mmdef:'))
        if self.companyName is not None:
            showIndent(write, level)
            write('<%scompanyName>%s</%scompanyName>\n' % ('mmdef:', quote_xml(self.companyName), 'mmdef:'))
        if self.category is not None:
            showIndent(write, level)
            write('<%scategory>%s</%scategory>\n' % ('mmdef:', quote_xml(self.category), 'mmdef:'))
        if self.classificationDetails is not None:
            self.classificationDetails.export(write, level, namespace_, name_='classificationDetails')
    def hasContent_(self):
        if (
            self.classificationName is not None or
            self.companyName is not None or
            self.category is not None or
            self.classificationDetails is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.append('type')
            self.type_ = value
            self.validate_ClassificationTypeEnum(self.type_)    # validate type ClassificationTypeEnum
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'classificationName':
            classificationName_ = child_.text
            classificationName_ = self.gds_validate_string(classificationName_, node, 'classificationName')
            self.classificationName = classificationName_
        elif nodeName_ == 'companyName':
            companyName_ = child_.text
            companyName_ = self.gds_validate_string(companyName_, node, 'companyName')
            self.companyName = companyName_
        elif nodeName_ == 'category':
            category_ = child_.text
            category_ = self.gds_validate_string(category_, node, 'category')
            self.category = category_
        elif nodeName_ == 'classificationDetails':
            obj_ = classificationDetails.factory()
            obj_.build(child_)
            self.set_classificationDetails(obj_)
# end class classificationObject


class classificationDetails(GeneratedsSuper):
    """Details of the classification, giving product details, particularly
    useful for anti-virus scanner detections."""
    subclass = None
    superclass = None
    def __init__(self, definitionVersion=None, detectionAddedTimeStamp=None, detectionShippedTimeStamp=None, product=None, productVersion=None):
        self.definitionVersion = definitionVersion
        self.detectionAddedTimeStamp = detectionAddedTimeStamp
        self.detectionShippedTimeStamp = detectionShippedTimeStamp
        self.product = product
        self.productVersion = productVersion
    def factory(*args_, **kwargs_):
        if classificationDetails.subclass:
            return classificationDetails.subclass(*args_, **kwargs_)
        else:
            return classificationDetails(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_definitionVersion(self): return self.definitionVersion
    def set_definitionVersion(self, definitionVersion): self.definitionVersion = definitionVersion
    def get_detectionAddedTimeStamp(self): return self.detectionAddedTimeStamp
    def set_detectionAddedTimeStamp(self, detectionAddedTimeStamp): self.detectionAddedTimeStamp = detectionAddedTimeStamp
    def get_detectionShippedTimeStamp(self): return self.detectionShippedTimeStamp
    def set_detectionShippedTimeStamp(self, detectionShippedTimeStamp): self.detectionShippedTimeStamp = detectionShippedTimeStamp
    def get_product(self): return self.product
    def set_product(self, product): self.product = product
    def get_productVersion(self): return self.productVersion
    def set_productVersion(self, productVersion): self.productVersion = productVersion
    def export(self, write, level, namespace_='', name_='classificationDetails', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='classificationDetails')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='classificationDetails'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='classificationDetails', fromsubclass_=False):
        if self.definitionVersion is not None:
            showIndent(write, level)
            write('<%sdefinitionVersion>%s</%sdefinitionVersion>\n' % (namespace_, quote_xml(self.definitionVersion), namespace_))
        if self.detectionAddedTimeStamp is not None:
            showIndent(write, level)
            write('<%sdetectionAddedTimeStamp>%s</%sdetectionAddedTimeStamp>\n' % (namespace_, quote_xml(self.detectionAddedTimeStamp), namespace_))
        if self.detectionShippedTimeStamp is not None:
            showIndent(write, level)
            write('<%sdetectionShippedTimeStamp>%s</%sdetectionShippedTimeStamp>\n' % (namespace_, quote_xml(self.detectionShippedTimeStamp), namespace_))
        if self.product is not None:
            showIndent(write, level)
            write('<%sproduct>%s</%sproduct>\n' % (namespace_, quote_xml(self.product), namespace_))
        if self.productVersion is not None:
            showIndent(write, level)
            write('<%sproductVersion>%s</%sproductVersion>\n' % (namespace_, quote_xml(self.productVersion), namespace_))
    def hasContent_(self):
        if (
            self.definitionVersion is not None or
            self.detectionAddedTimeStamp is not None or
            self.detectionShippedTimeStamp is not None or
            self.product is not None or
            self.productVersion is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'definitionVersion':
            definitionVersion_ = child_.text
            definitionVersion_ = self.gds_validate_string(definitionVersion_, node, 'definitionVersion')
            self.definitionVersion = definitionVersion_
        elif nodeName_ == 'detectionAddedTimeStamp':
            detectionAddedTimeStamp_ = child_.text
            detectionAddedTimeStamp_ = self.gds_validate_string(detectionAddedTimeStamp_, node, 'detectionAddedTimeStamp')
            self.detectionAddedTimeStamp = detectionAddedTimeStamp_
        elif nodeName_ == 'detectionShippedTimeStamp':
            detectionShippedTimeStamp_ = child_.text
            detectionShippedTimeStamp_ = self.gds_validate_string(detectionShippedTimeStamp_, node, 'detectionShippedTimeStamp')
            self.detectionShippedTimeStamp = detectionShippedTimeStamp_
        elif nodeName_ == 'product':
            product_ = child_.text
            product_ = self.gds_validate_string(product_, node, 'product')
            self.product = product_
        elif nodeName_ == 'productVersion':
            productVersion_ = child_.text
            productVersion_ = self.gds_validate_string(productVersion_, node, 'productVersion')
            self.productVersion = productVersion_
# end class classificationDetails


class fieldDataEntry(GeneratedsSuper):
    """Data structure to hold prevalence information. The data includes a
    reference to another object (which is an xpath expression
    pointing to an object inside the 'ref' element), together with a
    time period (startDate -> endDate), an origin - where the object
    came from, and various location tags. This allows rich
    information on prevalence to be recorded. By convention, time
    periods should be wherever possible standard time periods, e.g.
    minute, hour, 24 hours, week, month, quarter, year. This will
    facilitate combination of data from multiple sources. To
    represent a single entry, make startDate == endDate. Commonality
    is calculated from the sightings of malware objects (and so such
    calculation is easier to automate). Importance is reserved for
    cases when “commonality” is not available or if there is a
    need to communicate the importance when commonality is low. We
    define the commonality on a scale 0 to 100 (0 means “never
    found in the field” and 100 means “found very
    frequently”). Scaling commonality to 0..100 range instead of
    using actual sample counts is to avoid the effect of the user
    base size on the commonality. We derive commonality from the
    number of affected computers – not from the number of samples
    (for example, a hundred parasitic infections of the same virus
    on a single computer are to be counted as one). To calculate the
    commonality we use two-stage approach and logarithmic scale: -
    If the number of affected users exceeds 0.1% of your user base
    (more frequent than 1 in a 1000) set commonality to “100” -
    Otherwise, calculate the ratio of infected computers amongst
    your user base by dividing the real number of affected computers
    ‘n’ by the total number ‘N’ - Apply the following
    formula to get the commonality –( log2(1+n*1000/N) ) * 100 -
    Round to the closest integer Obviously, the calculation above
    can only be applied to counting of malware sightings on
    desktops. If telemetry is collected from a fraction of such
    desktops then an appropriate correction should be used. For all
    other cases (e.g. sighting on gateways, in some network security
    appliance, on an ISP level, etc.) please exercise your best
    judgment and apply provided desktop guideline as an example to
    make sure the commonality factor is as comparable as possible.
    For a URL object the commonality could reflect, for example, how
    widely it was spammed. “Importance” should not be used
    together with “commonality” (unless commonality=“0”) to
    avoid possible confusion. High “importance”, for example,
    can be assigned to samples that are over-hyped by media when
    their commonality is still “0”. Use the following guidelines
    for “importance” which is also defined on a scale 0..100:
    100 – you’d expect your CEO and/or media to call you any
    second about this object 80 – you might get a call from your
    CEO and/or media 60 – you’d expect your boss to call you any
    second 40 – you might get a call from your boss 20 – someone
    is very likely to contact you about this object 10 – you might
    get contacted about this object 0 – you’d be surprised if
    anyone would ever contact you about this object"""
    subclass = None
    superclass = None
    def __init__(self, references=None, startDate=None, endDate=None, firstSeenDate=None, origin=None, commonality=None, volume=None, importance=None, location=None):
        self.references = references
        self.startDate = startDate
        self.endDate = endDate
        self.firstSeenDate = firstSeenDate
        self.origin = origin
        self.commonality = commonality
        if volume is None:
            self.volume = []
        else:
            self.volume = volume
        self.importance = importance
        self.location = location
    def factory(*args_, **kwargs_):
        if fieldDataEntry.subclass:
            return fieldDataEntry.subclass(*args_, **kwargs_)
        else:
            return fieldDataEntry(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_references(self): return self.references
    def set_references(self, references): self.references = references
    def get_startDate(self): return self.startDate
    def set_startDate(self, startDate): self.startDate = startDate
    def get_endDate(self): return self.endDate
    def set_endDate(self, endDate): self.endDate = endDate
    def get_firstSeenDate(self): return self.firstSeenDate
    def set_firstSeenDate(self, firstSeenDate): self.firstSeenDate = firstSeenDate
    def get_origin(self): return self.origin
    def set_origin(self, origin): self.origin = origin
    def validate_OriginTypeEnum(self, value):
        # Validate type OriginTypeEnum, a restriction on xs:string.
        pass
    def get_commonality(self): return self.commonality
    def set_commonality(self, commonality): self.commonality = commonality
    def validate_intBetween0and100(self, value):
        # Validate type intBetween0and100, a restriction on xs:integer.
        pass
    def get_volume(self): return self.volume
    def set_volume(self, volume): self.volume = volume
    def add_volume(self, value): self.volume.append(value)
    def insert_volume(self, index, value): self.volume[index] = value
    def get_importance(self): return self.importance
    def set_importance(self, importance): self.importance = importance
    def get_location(self): return self.location
    def set_location(self, location): self.location = location
    def export(self, write, level, namespace_='', name_='fieldDataEntry', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='fieldDataEntry')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='fieldDataEntry'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='fieldDataEntry', fromsubclass_=False):
        if self.references is not None:
            self.references.export(write, level, namespace_, name_='references', )
        if self.startDate is not None:
            showIndent(write, level)
            write('<%sstartDate>%s</%sstartDate>\n' % (namespace_, quote_xml(self.startDate), namespace_))
        if self.endDate is not None:
            showIndent(write, level)
            write('<%sendDate>%s</%sendDate>\n' % (namespace_, quote_xml(self.endDate), namespace_))
        if self.firstSeenDate is not None:
            showIndent(write, level)
            write('<%sfirstSeenDate>%s</%sfirstSeenDate>\n' % (namespace_, quote_xml(self.firstSeenDate), namespace_))
        if self.origin is not None:
            showIndent(write, level)
            write('<%sorigin>%s</%sorigin>\n' % (namespace_, quote_xml(self.origin), namespace_))
        if self.commonality is not None:
            showIndent(write, level)
            write('<%scommonality>%s</%scommonality>\n' % (namespace_, self.gds_format_integer(self.commonality, input_name='commonality'), namespace_))
        for volume_ in self.volume:
            volume_.export(write, level, namespace_, name_='volume')
        if self.importance is not None:
            showIndent(write, level)
            write('<%simportance>%s</%simportance>\n' % (namespace_, self.gds_format_integer(self.importance, input_name='importance'), namespace_))
        if self.location is not None:
            self.location.export(write, level, namespace_, name_='location')
    def hasContent_(self):
        if (
            self.references is not None or
            self.startDate is not None or
            self.endDate is not None or
            self.firstSeenDate is not None or
            self.origin is not None or
            self.commonality is not None or
            self.volume or
            self.importance is not None or
            self.location is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'references':
            obj_ = references.factory()
            obj_.build(child_)
            self.set_references(obj_)
        elif nodeName_ == 'startDate':
            startDate_ = child_.text
            startDate_ = self.gds_validate_string(startDate_, node, 'startDate')
            self.startDate = startDate_
        elif nodeName_ == 'endDate':
            endDate_ = child_.text
            endDate_ = self.gds_validate_string(endDate_, node, 'endDate')
            self.endDate = endDate_
        elif nodeName_ == 'firstSeenDate':
            firstSeenDate_ = child_.text
            firstSeenDate_ = self.gds_validate_string(firstSeenDate_, node, 'firstSeenDate')
            self.firstSeenDate = firstSeenDate_
        elif nodeName_ == 'origin':
            origin_ = child_.text
            origin_ = self.gds_validate_string(origin_, node, 'origin')
            self.origin = origin_
            self.validate_OriginTypeEnum(self.origin)    # validate type OriginTypeEnum
        elif nodeName_ == 'commonality':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'commonality')
            self.commonality = ival_
            self.validate_intBetween0and100(self.commonality)    # validate type intBetween0and100
        elif nodeName_ == 'volume':
            obj_ = volume.factory()
            obj_.build(child_)
            self.volume.append(obj_)
        elif nodeName_ == 'importance':
            sval_ = child_.text
            try:
                ival_ = int(sval_)
            except (TypeError, ValueError), exp:
                raise_parse_error(child_, 'requires integer: %s' % exp)
            ival_ = self.gds_validate_integer(ival_, node, 'importance')
            self.importance = ival_
            self.validate_intBetween0and100(self.importance)    # validate type intBetween0and100
        elif nodeName_ == 'location':
            obj_ = location.factory()
            obj_.build(child_)
            self.set_location(obj_)
# end class fieldDataEntry


class references(GeneratedsSuper):
    """The objects the prevalence information pertains to."""
    subclass = None
    superclass = None
    def __init__(self, ref=None):
        if ref is None:
            self.ref = []
        else:
            self.ref = ref
    def factory(*args_, **kwargs_):
        if references.subclass:
            return references.subclass(*args_, **kwargs_)
        else:
            return references(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_ref(self): return self.ref
    def set_ref(self, ref): self.ref = ref
    def add_ref(self, value): self.ref.append(value)
    def insert_ref(self, index, value): self.ref[index] = value
    def export(self, write, level, namespace_='', name_='references', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='references')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='references'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='references', fromsubclass_=False):
        for ref_ in self.ref:
            ref_.export(write, level, namespace_, name_='ref')
    def hasContent_(self):
        if (
            self.ref
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'ref':
            obj_ = reference.factory()
            obj_.build(child_)
            self.ref.append(obj_)
# end class references


class volume(GeneratedsSuper):
    """Quantitive measurements of prevalence."""
    subclass = None
    superclass = None
    def __init__(self, units=None, valueOf_=None):
        self.units = _cast(None, units)
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if volume.subclass:
            return volume.subclass(*args_, **kwargs_)
        else:
            return volume(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_units(self): return self.units
    def set_units(self, units): self.units = units
    def validate_VolumeUnitsEnum(self, value):
        # Validate type VolumeUnitsEnum, a restriction on xs:string.
        pass
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='volume', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='volume')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='volume'):
        if self.units is not None and 'units' not in already_processed:
            already_processed.append('units')
            write(' units=%s' % (quote_attrib(self.units), ))
    def exportChildren(self, write, level, namespace_='', name_='volume', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('units', node)
        if value is not None and 'units' not in already_processed:
            already_processed.append('units')
            self.units = value
            self.validate_VolumeUnitsEnum(self.units)    # validate type VolumeUnitsEnum
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class volume


class location(GeneratedsSuper):
    """Geolocation information for prevalence."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, valueOf_=None):
        self.type_ = _cast(None, type_)
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if location.subclass:
            return location.subclass(*args_, **kwargs_)
        else:
            return location(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def validate_LocationTypeEnum(self, value):
        # Validate type LocationTypeEnum, a restriction on xs:string.
        pass
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='location', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='location')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='location'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.append('type_')
            write(' type=%s' % (quote_attrib(self.type_), ))
    def exportChildren(self, write, level, namespace_='', name_='location', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.append('type')
            self.type_ = value
            self.validate_LocationTypeEnum(self.type_)    # validate type LocationTypeEnum
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class location


class reference(GeneratedsSuper):
    """Reference element used to hold xpath expressions to objects, for
    example file[@id="12345"]."""
    subclass = None
    superclass = None
    def __init__(self, valueOf_=None):
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if reference.subclass:
            return reference.subclass(*args_, **kwargs_)
        else:
            return reference(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='reference', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='reference')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='reference'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='reference', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class reference


class property(GeneratedsSuper):
    """A property."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, valueOf_=None):
        self.type_ = _cast(None, type_)
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if property.subclass:
            return property.subclass(*args_, **kwargs_)
        else:
            return property(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def validate_PropertyTypeEnum(self, value):
        # Validate type PropertyTypeEnum, a restriction on xs:string.
        pass
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='property', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='property')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='property'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.append('type_')
            write(' type=%s' % (quote_attrib(self.type_), ))
    def exportChildren(self, write, level, namespace_='', name_='property', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.append('type')
            self.type_ = value
            self.validate_PropertyTypeEnum(self.type_)    # validate type PropertyTypeEnum
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class property


class objectProperty(GeneratedsSuper):
    """Property; a reference to the object, a timestamp and an unbounded
    set of properties. This is used to describe extra information
    about an object. For example, to show the url parameter strings
    associated with a particular URI object. Or to show file names
    associated with a particular file. Properties can also be
    applied to relationships, by referencing the relationship by id.
    This allows use such as e.g. recording the post data sent in an
    http request between a malware (file object) and a uri (uri
    object)."""
    subclass = None
    superclass = None
    def __init__(self, id=None, references=None, timestamp=None, property=None):
        self.id = _cast(None, id)
        self.references = references
        self.timestamp = timestamp
        if property is None:
            self.property = []
        else:
            self.property = property
    def factory(*args_, **kwargs_):
        if objectProperty.subclass:
            return objectProperty.subclass(*args_, **kwargs_)
        else:
            return objectProperty(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_references(self): return self.references
    def set_references(self, references): self.references = references
    def get_timestamp(self): return self.timestamp
    def set_timestamp(self, timestamp): self.timestamp = timestamp
    def get_property(self): return self.property
    def set_property(self, property): self.property = property
    def add_property(self, value): self.property.append(value)
    def insert_property(self, index, value): self.property[index] = value
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='objectProperty', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='objectProperty')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='objectProperty'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='', name_='objectProperty', fromsubclass_=False):
        if self.references is not None:
            self.references.export(write, level, namespace_, name_='references', )
        if self.timestamp is not None:
            showIndent(write, level)
            write('<%stimestamp>%s</%stimestamp>\n' % (namespace_, quote_xml(self.timestamp), namespace_))
        for property_ in self.property:
            property_.export(write, level, namespace_, name_='property')
    def hasContent_(self):
        if (
            self.references is not None or
            self.timestamp is not None or
            self.property
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'references':
            obj_ = references.factory()
            obj_.build(child_)
            self.set_references(obj_)
        elif nodeName_ == 'timestamp':
            timestamp_ = child_.text
            timestamp_ = self.gds_validate_string(timestamp_, node, 'timestamp')
            self.timestamp = timestamp_
        elif nodeName_ == 'property':
            obj_ = property.factory()
            obj_.build(child_)
            self.property.append(obj_)
# end class objectProperty


class relationship(GeneratedsSuper):
    """Relationships are used to express relationships between objects, and
    dates. Relationships have a type (an attribute with a defined
    list of allowed relationships), source (a set of xpath
    references to the parent end of the relationship), target (xpath
    references to the other end of the relationship) and an optional
    date. The linking of objects with types is a powerful way of
    describing data. The dates can be used to provide context. For
    example, to assign a classification to an object, that can done
    with an "isClassifiedAs" relationship, with the date meaning
    that that was the data that that classification was assigned. To
    show urls and the last visited data, this can be expressed as a
    "verifiedBy" relationship between the urls and the entity doing
    the verification, with the date interpreted as the verification
    date."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, id=None, source=None, target=None, timestamp=None):
        self.type_ = _cast(None, type_)
        self.id = _cast(None, id)
        self.source = source
        self.target = target
        self.timestamp = timestamp
    def factory(*args_, **kwargs_):
        if relationship.subclass:
            return relationship.subclass(*args_, **kwargs_)
        else:
            return relationship(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_source(self): return self.source
    def set_source(self, source): self.source = source
    def get_target(self): return self.target
    def set_target(self, target): self.target = target
    def get_timestamp(self): return self.timestamp
    def set_timestamp(self, timestamp): self.timestamp = timestamp
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def validate_RelationshipTypeEnum(self, value):
        # Validate type RelationshipTypeEnum, a restriction on xs:string.
        pass
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='relationship', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='relationship')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='relationship'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.append('type_')
            write(' type=%s' % (quote_attrib(self.type_), ))
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id), ))
    def exportChildren(self, write, level, namespace_='', name_='relationship', fromsubclass_=False):
        if self.source is not None:
            self.source.export(write, level, namespace_, name_='source', )
        if self.target is not None:
            self.target.export(write, level, namespace_, name_='target', )
        if self.timestamp is not None:
            showIndent(write, level)
            write('<%stimestamp>%s</%stimestamp>\n' % (namespace_, quote_xml(self.timestamp), namespace_))
    def hasContent_(self):
        if (
            self.source is not None or
            self.target is not None or
            self.timestamp is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.append('type')
            self.type_ = value
            self.validate_RelationshipTypeEnum(self.type_)    # validate type RelationshipTypeEnum
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'source':
            obj_ = source.factory()
            obj_.build(child_)
            self.set_source(obj_)
        elif nodeName_ == 'target':
            obj_ = target.factory()
            obj_.build(child_)
            self.set_target(obj_)
        elif nodeName_ == 'timestamp':
            timestamp_ = child_.text
            timestamp_ = self.gds_validate_string(timestamp_, node, 'timestamp')
            self.timestamp = timestamp_
# end class relationship


class source(GeneratedsSuper):
    """References to objects at the parent end of the relationship."""
    subclass = None
    superclass = None
    def __init__(self, ref=None):
        if ref is None:
            self.ref = []
        else:
            self.ref = ref
    def factory(*args_, **kwargs_):
        if source.subclass:
            return source.subclass(*args_, **kwargs_)
        else:
            return source(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_ref(self): return self.ref
    def set_ref(self, ref): self.ref = ref
    def add_ref(self, value): self.ref.append(value)
    def insert_ref(self, index, value): self.ref[index] = value
    def export(self, write, level, namespace_='', name_='source', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='source')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='source'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='source', fromsubclass_=False):
        for ref_ in self.ref:
            ref_.export(write, level, namespace_, name_='ref')
    def hasContent_(self):
        if (
            self.ref
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'ref':
            obj_ = reference.factory()
            obj_.build(child_)
            self.ref.append(obj_)
# end class source


class target(GeneratedsSuper):
    """References to objects at the child end of the relationship."""
    subclass = None
    superclass = None
    def __init__(self, ref=None):
        if ref is None:
            self.ref = []
        else:
            self.ref = ref
    def factory(*args_, **kwargs_):
        if target.subclass:
            return target.subclass(*args_, **kwargs_)
        else:
            return target(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_ref(self): return self.ref
    def set_ref(self, ref): self.ref = ref
    def add_ref(self, value): self.ref.append(value)
    def insert_ref(self, index, value): self.ref[index] = value
    def export(self, write, level, namespace_='', name_='target', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='target')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='target'):
        pass
    def exportChildren(self, write, level, namespace_='', name_='target', fromsubclass_=False):
        for ref_ in self.ref:
            ref_.export(write, level, namespace_, name_='ref')
    def hasContent_(self):
        if (
            self.ref
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        pass
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'ref':
            obj_ = reference.factory()
            obj_.build(child_)
            self.ref.append(obj_)
# end class target


class softwarePackageObject(GeneratedsSuper):
    """Software package object, used to store information about a software
    package, such as the vendor and version. Intended primarily for
    the clean-file metadata sharing use case."""
    subclass = None
    superclass = None
    def __init__(self, id=None, vendor=None, productgroup=None, product=None, version=None, update=None, edition=None, language=None, CPEname=None):
        self.id = _cast(None, id)
        self.vendor = vendor
        self.productgroup = productgroup
        self.product = product
        self.version = version
        self.update = update
        self.edition = edition
        self.language = language
        self.CPEname = CPEname
    def factory(*args_, **kwargs_):
        if softwarePackageObject.subclass:
            return softwarePackageObject.subclass(*args_, **kwargs_)
        else:
            return softwarePackageObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_vendor(self): return self.vendor
    def set_vendor(self, vendor): self.vendor = vendor
    def get_productgroup(self): return self.productgroup
    def set_productgroup(self, productgroup): self.productgroup = productgroup
    def get_product(self): return self.product
    def set_product(self, product): self.product = product
    def get_version(self): return self.version
    def set_version(self, version): self.version = version
    def get_update(self): return self.update
    def set_update(self, update): self.update = update
    def get_edition(self): return self.edition
    def set_edition(self, edition): self.edition = edition
    def get_language(self): return self.language
    def set_language(self, language): self.language = language
    def get_CPEname(self): return self.CPEname
    def set_CPEname(self, CPEname): self.CPEname = CPEname
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='softwarePackageObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='softwarePackageObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='softwarePackageObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='softwarePackageObject', fromsubclass_=False):
        if self.vendor is not None:
            showIndent(write, level)
            write('<%svendor>%s</%svendor>\n' % (namespace_, quote_xml(self.vendor), namespace_))
        if self.productgroup is not None:
            showIndent(write, level)
            write('<%sproductgroup>%s</%sproductgroup>\n' % (namespace_, quote_xml(self.productgroup), namespace_))
        if self.product is not None:
            showIndent(write, level)
            write('<%sproduct>%s</%sproduct>\n' % (namespace_, quote_xml(self.product), namespace_))
        if self.version is not None:
            showIndent(write, level)
            write('<%sversion>%s</%sversion>\n' % (namespace_, quote_xml(self.version), namespace_))
        if self.update is not None:
            showIndent(write, level)
            write('<%supdate>%s</%supdate>\n' % (namespace_, quote_xml(self.update), namespace_))
        if self.edition is not None:
            showIndent(write, level)
            write('<%sedition>%s</%sedition>\n' % (namespace_, quote_xml(self.edition), namespace_))
        if self.language is not None:
            showIndent(write, level)
            write('<%slanguage>%s</%slanguage>\n' % (namespace_, quote_xml(self.language), namespace_))
        if self.CPEname is not None:
            self.CPEname.export(write, level, namespace_, name_='CPEname')
    def hasContent_(self):
        if (
            self.vendor is not None or
            self.productgroup is not None or
            self.product is not None or
            self.version is not None or
            self.update is not None or
            self.edition is not None or
            self.language is not None or
            self.CPEname is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'vendor':
            vendor_ = child_.text
            vendor_ = self.gds_validate_string(vendor_, node, 'vendor')
            self.vendor = vendor_
        elif nodeName_ == 'productgroup':
            productgroup_ = child_.text
            productgroup_ = self.gds_validate_string(productgroup_, node, 'productgroup')
            self.productgroup = productgroup_
        elif nodeName_ == 'product':
            product_ = child_.text
            product_ = self.gds_validate_string(product_, node, 'product')
            self.product = product_
        elif nodeName_ == 'version':
            version_ = child_.text
            version_ = self.gds_validate_string(version_, node, 'version')
            self.version = version_
        elif nodeName_ == 'update':
            update_ = child_.text
            update_ = self.gds_validate_string(update_, node, 'update')
            self.update = update_
        elif nodeName_ == 'edition':
            edition_ = child_.text
            edition_ = self.gds_validate_string(edition_, node, 'edition')
            self.edition = edition_
        elif nodeName_ == 'language':
            language_ = child_.text
            language_ = self.gds_validate_string(language_, node, 'language')
            self.language = language_
        elif nodeName_ == 'CPEname':
            obj_ = CPEname.factory()
            obj_.build(child_)
            self.set_CPEname(obj_)
# end class softwarePackageObject


class CPEname(GeneratedsSuper):
    """The Common Platform Enumeration, or CPE, name of the package if one
    exists. CPE is a structured naming scheme for IT systems,
    software, and packages. For more information on CPE see
    http://cpe.mitre.org. For the official CPE dictionary see
    http://nvd.nist.gov/cpe.cfm.The version of CPE that is used for
    the name in the CPEname element. As of 10/04/2011 this is 2.2."""
    subclass = None
    superclass = None
    def __init__(self, cpeVersion=None, valueOf_=None):
        self.cpeVersion = _cast(None, cpeVersion)
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if CPEname.subclass:
            return CPEname.subclass(*args_, **kwargs_)
        else:
            return CPEname(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_cpeVersion(self): return self.cpeVersion
    def set_cpeVersion(self, cpeVersion): self.cpeVersion = cpeVersion
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='CPEname', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='CPEname')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='CPEname'):
        if self.cpeVersion is not None and 'cpeVersion' not in already_processed:
            already_processed.append('cpeVersion')
            write(' cpeVersion=%s' % (quote_attrib(self.cpeVersion)))
    def exportChildren(self, write, level, namespace_='', name_='CPEname', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('cpeVersion', node)
        if value is not None and 'cpeVersion' not in already_processed:
            already_processed.append('cpeVersion')
            self.cpeVersion = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class CPEname


class digitalSignatureObject(GeneratedsSuper):
    """Digital signature object, used to hold information about digitally
    signed binaries with regards to the certificate used and its
    validity."""
    subclass = None
    superclass = None
    def __init__(self, type_=None, id=None, certificateIssuer=None, certificateSubject=None, certificateValidity=None, certificateRevocationTimestamp=None, signingTimestamp=None):
        self.type_ = _cast(None, type_)
        self.id = _cast(None, id)
        self.certificateIssuer = certificateIssuer
        self.certificateSubject = certificateSubject
        self.certificateValidity = certificateValidity
        self.certificateRevocationTimestamp = certificateRevocationTimestamp
        self.signingTimestamp = signingTimestamp
    def factory(*args_, **kwargs_):
        if digitalSignatureObject.subclass:
            return digitalSignatureObject.subclass(*args_, **kwargs_)
        else:
            return digitalSignatureObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_certificateIssuer(self): return self.certificateIssuer
    def set_certificateIssuer(self, certificateIssuer): self.certificateIssuer = certificateIssuer
    def get_certificateSubject(self): return self.certificateSubject
    def set_certificateSubject(self, certificateSubject): self.certificateSubject = certificateSubject
    def get_certificateValidity(self): return self.certificateValidity
    def set_certificateValidity(self, certificateValidity): self.certificateValidity = certificateValidity
    def get_certificateRevocationTimestamp(self): return self.certificateRevocationTimestamp
    def set_certificateRevocationTimestamp(self, certificateRevocationTimestamp): self.certificateRevocationTimestamp = certificateRevocationTimestamp
    def get_signingTimestamp(self): return self.signingTimestamp
    def set_signingTimestamp(self, signingTimestamp): self.signingTimestamp = signingTimestamp
    def get_type(self): return self.type_
    def set_type(self, type_): self.type_ = type_
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='digitalSignatureObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='digitalSignatureObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='digitalSignatureObject'):
        if self.type_ is not None and 'type_' not in already_processed:
            already_processed.append('type_')
            write(' type=%s' % (quote_attrib(self.type_)))
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='digitalSignatureObject', fromsubclass_=False):
        if self.certificateIssuer is not None:
            showIndent(write, level)
            write('<%scertificateIssuer>%s</%scertificateIssuer>\n' % (namespace_, quote_xml(self.certificateIssuer), namespace_))
        if self.certificateSubject is not None:
            showIndent(write, level)
            write('<%scertificateSubject>%s</%scertificateSubject>\n' % (namespace_, quote_xml(self.certificateSubject), namespace_))
        if self.certificateValidity is not None:
            showIndent(write, level)
            write('<%scertificateValidity>%s</%scertificateValidity>\n' % (namespace_, self.gds_format_boolean(self.gds_str_lower(str(self.certificateValidity)), input_name='certificateValidity'), namespace_))
        if self.certificateRevocationTimestamp is not None:
            showIndent(write, level)
            write('<%scertificateRevocationTimestamp>%s</%scertificateRevocationTimestamp>\n' % (namespace_, quote_xml(self.certificateRevocationTimestamp), namespace_))
        if self.signingTimestamp is not None:
            self.signingTimestamp.export(write, level, namespace_, name_='signingTimestamp')
    def hasContent_(self):
        if (
            self.certificateIssuer is not None or
            self.certificateSubject is not None or
            self.certificateValidity is not None or
            self.certificateRevocationTimestamp is not None or
            self.signingTimestamp is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('type', node)
        if value is not None and 'type' not in already_processed:
            already_processed.append('type')
            self.type_ = value
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'certificateIssuer':
            certificateIssuer_ = child_.text
            certificateIssuer_ = self.gds_validate_string(certificateIssuer_, node, 'certificateIssuer')
            self.certificateIssuer = certificateIssuer_
        elif nodeName_ == 'certificateSubject':
            certificateSubject_ = child_.text
            certificateSubject_ = self.gds_validate_string(certificateSubject_, node, 'certificateSubject')
            self.certificateSubject = certificateSubject_
        elif nodeName_ == 'certificateValidity':
            sval_ = child_.text
            if sval_ in ('true', '1'):
                ival_ = True
            elif sval_ in ('false', '0'):
                ival_ = False
            else:
                raise_parse_error(child_, 'requires boolean')
            ival_ = self.gds_validate_boolean(ival_, node, 'certificateValidity')
            self.certificateValidity = ival_
        elif nodeName_ == 'certificateRevocationTimestamp':
            certificateRevocationTimestamp_ = child_.text
            certificateRevocationTimestamp_ = self.gds_validate_string(certificateRevocationTimestamp_, node, 'certificateRevocationTimestamp')
            self.certificateRevocationTimestamp = certificateRevocationTimestamp_
        elif nodeName_ == 'signingTimestamp':
            obj_ = signingTimestamp.factory()
            obj_.build(child_)
            self.set_signingTimestamp(obj_)
# end class digitalSignatureObject


class signingTimestamp(GeneratedsSuper):
    subclass = None
    superclass = None
    def __init__(self, valid=None, valueOf_=None):
        self.valid = _cast(bool, valid)
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if signingTimestamp.subclass:
            return signingTimestamp.subclass(*args_, **kwargs_)
        else:
            return signingTimestamp(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_valid(self): return self.valid
    def set_valid(self, valid): self.valid = valid
    def get_valueOf_(self): return self.valueOf_
    def set_valueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, write, level, namespace_='', name_='signingTimestamp', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='signingTimestamp')
        if self.hasContent_():
            write('>')
            write(quote_xml(self.valueOf_))
            self.exportChildren(write, level + 1, namespace_, name_)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='signingTimestamp'):
        if self.valid is not None and 'valid' not in already_processed:
            already_processed.append('valid')
            write(' valid="%s"' % self.gds_format_boolean(self.gds_str_lower(str(self.valid)), input_name='valid'))
    def exportChildren(self, write, level, namespace_='', name_='signingTimestamp', fromsubclass_=False):
        pass
    def hasContent_(self):
        if (
            self.valueOf_
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        self.valueOf_ = get_all_text_(node)
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('valid', node)
        if value is not None and 'valid' not in already_processed:
            already_processed.append('valid')
            if value in ('true', '1'):
                self.valid = True
            elif value in ('false', '0'):
                self.valid = False
            else:
                raise_parse_error(node, 'Bad boolean attribute')
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        pass
# end class signingTimestamp


class taggantObject(GeneratedsSuper):
    """Taggant object, for use in characterizing the software taggant that
    may be associated with a file or multiple files. For more
    information on the taggant system or the IEEE Malware Working
    Group that created it, please see
    http://standards.ieee.org/develop/indconn/icsg/malware.html."""
    subclass = None
    superclass = None
    def __init__(self, id=None, vendorID=None, taggantValidity=None, signingTimestamp=None):
        self.id = _cast(None, id)
        self.vendorID = vendorID
        self.taggantValidity = taggantValidity
        self.signingTimestamp = signingTimestamp
    def factory(*args_, **kwargs_):
        if taggantObject.subclass:
            return taggantObject.subclass(*args_, **kwargs_)
        else:
            return taggantObject(*args_, **kwargs_)
    factory = staticmethod(factory)
    def get_vendorID(self): return self.vendorID
    def set_vendorID(self, vendorID): self.vendorID = vendorID
    def get_taggantValidity(self): return self.taggantValidity
    def set_taggantValidity(self, taggantValidity): self.taggantValidity = taggantValidity
    def get_signingTimestamp(self): return self.signingTimestamp
    def set_signingTimestamp(self, signingTimestamp): self.signingTimestamp = signingTimestamp
    def get_id(self): return self.id
    def set_id(self, id): self.id = id
    def export(self, write, level, namespace_='', name_='taggantObject', namespacedef_=''):
        showIndent(write, level)
        write('<%s%s%s' % (namespace_, name_, namespacedef_ and ' ' + namespacedef_ or '', ))
        already_processed = []
        self.exportAttributes(write, level, already_processed, namespace_, name_='taggantObject')
        if self.hasContent_():
            write('>\n')
            self.exportChildren(write, level + 1, namespace_, name_)
            showIndent(write, level)
            write('</%s%s>\n' % (namespace_, name_))
        else:
            write('/>\n')
    def exportAttributes(self, write, level, already_processed, namespace_='', name_='taggantObject'):
        if self.id is not None and 'id' not in already_processed:
            already_processed.append('id')
            write(' id=%s' % (quote_attrib(self.id)))
    def exportChildren(self, write, level, namespace_='', name_='taggantObject', fromsubclass_=False):
        if self.vendorID is not None:
            showIndent(write, level)
            write('<%svendorID>%s</%svendorID>\n' % (namespace_, quote_xml(self.vendorID), namespace_))
        if self.taggantValidity is not None:
            showIndent(write, level)
            write('<%staggantValidity>%s</%staggantValidity>\n' % (namespace_, self.gds_format_boolean(self.gds_str_lower(str(self.taggantValidity)), input_name='taggantValidity'), namespace_))
        if self.signingTimestamp is not None:
            self.signingTimestamp.export(write, level, namespace_, name_='signingTimestamp')
    def hasContent_(self):
        if (
            self.vendorID is not None or
            self.taggantValidity is not None or
            self.signingTimestamp is not None
            ):
            return True
        else:
            return False
    def build(self, node):
        self.buildAttributes(node, node.attrib, [])
        for child in node:
            nodeName_ = Tag_pattern_.match(child.tag).groups()[-1]
            self.buildChildren(child, node, nodeName_)
    def buildAttributes(self, node, attrs, already_processed):
        value = find_attr_value_('id', node)
        if value is not None and 'id' not in already_processed:
            already_processed.append('id')
            self.id = value
    def buildChildren(self, child_, node, nodeName_, fromsubclass_=False):
        if nodeName_ == 'vendorID':
            vendorID_ = child_.text
            vendorID_ = self.gds_validate_string(vendorID_, node, 'vendorID')
            self.vendorID = vendorID_
        elif nodeName_ == 'taggantValidity':
            sval_ = child_.text
            if sval_ in ('true', '1'):
                ival_ = True
            elif sval_ in ('false', '0'):
                ival_ = False
            else:
                raise_parse_error(child_, 'requires boolean')
            ival_ = self.gds_validate_boolean(ival_, node, 'taggantValidity')
            self.taggantValidity = ival_
        elif nodeName_ == 'signingTimestamp':
            obj_ = signingTimestamp.factory()
            obj_.build(child_)
            self.set_signingTimestamp(obj_)
# end class taggantObject


USAGE_TEXT = """
Usage: python <Parser>.py [ -s ] <in_xml_file>
"""

def usage():
    print USAGE_TEXT
    sys.exit(1)

def parse(inFileName):
    doc = parsexml_(inFileName)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'malwareMetaData'
        rootClass = malwareMetaData
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('<?xml version="1.0" ?>\n')
    rootObj.export(sys.stdout, 0, name_=rootTag, 
        namespacedef_='')
    return rootObj


def parseString(inString):
    from StringIO import StringIO
    doc = parsexml_(StringIO(inString))
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'malwareMetaData'
        rootClass = malwareMetaData
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('<?xml version="1.0" ?>\n')
    rootObj.export(sys.stdout, 0, name_="malwareMetaData",
        namespacedef_='')
    return rootObj


def parseLiteral(inFileName):
    doc = parsexml_(inFileName)
    rootNode = doc.getroot()
    rootTag, rootClass = get_root_tag(rootNode)
    if rootClass is None:
        rootTag = 'malwareMetaData'
        rootClass = malwareMetaData
    rootObj = rootClass.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('#from mmdef import *\n\n')
    sys.stdout.write('import mmdef as model_\n\n')
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
    "ASNObject",
    "CPEname",
    "IPAddress",
    "IPObject",
    "classificationDetails",
    "classificationObject",
    "digitalSignatureObject",
    "domainObject",
    "entityObject",
    "extraHash",
    "fieldData",
    "fieldDataEntry",
    "fileObject",
    "location",
    "malwareMetaData",
    "objectProperties",
    "objectProperty",
    "objects",
    "property",
    "reference",
    "references",
    "registryObject",
    "relationship",
    "relationships",
    "signingTimestamp",
    "softwarePackageObject",
    "source",
    "taggantObject",
    "target",
    "uriObject",
    "volume"
    ]
