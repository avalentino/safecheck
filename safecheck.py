#!/usr/bin/env python3

# Copyright (C) 2011-2012 S[&]T, The Netherlands.

VERSION = "2.1"

import hashlib
import numpy
import os
import subprocess
import sys
import tempfile
from xml.etree.ElementTree import parse

helptext = """\
Usage:
    safecheck [-V] <SAFE folder> [<SAFE folder> ...]
        Perform an internal constency check on the given SAFE product.
        Note that the product must be unzipped.

        Use -V option to produce system compatible log messages

    safecheck -h, --help
        Show help (this text)

    safecheck -v, --version
        Print the version number of safecheck and exit

"""

versiontext = "SAFE Internal Consistency Checker (safecheck) v" + VERSION + "\n" + \
    "Copyright (C) 2011-2012 S[&]T, The Netherlands.\n"


NSXFDU = "{urn:ccsds:schema:xfdu:1}"


verbose = False
current_product = None


# status=[debug, info, warning, error, alert]
# kwargs=[tags, filename]
def report_message(message, status="info", **kwargs):
    if verbose:
        info = [status]
        for kw in kwargs:
            info.append("%s:\"%s\"" % (kw, kwargs[kw]))
        if current_product is not None:
            info.append("filename:\"%s\"" % (current_product,))
        for line in message.split('\n'):
            print("[%s] %s" % (' '.join(info), line))
        sys.stdout.flush()


def report_error(message, **kwargs):
    if verbose:
        report_message(message, status="error", **kwargs)
    elif 'tags' in kwargs:
        print("ERROR: [%s] %s" % (kwargs['tags'], message))
    else:
        print("ERROR: %s" % (message,))
    sys.stdout.flush()


def report_warning(message, **kwargs):
    if verbose:
        report_message(message, status="warning", **kwargs)
    elif 'tags' in kwargs:
        print("WARNING: [%s] %s" % (kwargs['tags'], message))
    else:
        print("WARNING: %s" % (message,))
    sys.stdout.flush()


manifest_schema = """\
<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xfdu="urn:ccsds:schema:xfdu:1" targetNamespace="urn:ccsds:schema:xfdu:1" elementFormDefault="unqualified" attributeFormDefault="unqualified">
  <xs:simpleType name="locatorTypeType">
    <xs:restriction base="xs:string">
      <xs:enumeration value="URL"/>
      <xs:enumeration value="OTHER"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="otherLocatorTypeType">
    <xs:restriction base="xs:string"/>
  </xs:simpleType>
  <xs:attributeGroup name="LOCATION">
    <xs:attribute name="locatorType" use="required" type="xfdu:locatorTypeType"/>
    <xs:attribute name="otherLocatorType" type="xfdu:otherLocatorTypeType"/>
  </xs:attributeGroup>
  <xs:attributeGroup name="registrationGroup">
    <xs:attribute name="registrationAuthority" type="xs:string" use="optional"/>
    <xs:attribute name="registeredID" type="xs:string" use="optional"/>
  </xs:attributeGroup>
  <xs:simpleType name="vocabularyNameType">
    <xs:restriction base="xs:string"/>
  </xs:simpleType>
  <xs:simpleType name="versionType">
    <xs:restriction base="xs:string"/>
  </xs:simpleType>
  <xs:simpleType name="mimeTypeType">
    <xs:restriction base="xs:string"/>
  </xs:simpleType>
  <xs:simpleType name="checksumNameType">
    <xs:restriction base="xs:string">
      <xs:enumeration value="MD5"/>
      <xs:enumeration value="CRC32"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:simpleType name="combinationMethodType">
    <xs:restriction base="xs:string">
      <xs:enumeration value="concat"/>
    </xs:restriction>
  </xs:simpleType>
  <xs:attribute name="namespace" type="xs:string"/>
  <xs:complexType name="referenceType">
    <xs:sequence/>
    <xs:attribute name="href" type="xs:string" use="required"/>
    <xs:attribute name="ID" type="xs:ID"/>
    <xs:attribute name="textInfo" type="xs:string"/>
    <xs:attributeGroup ref="xfdu:LOCATION"/>
    <xs:attribute name="locator" type="xs:string" use="optional" default="/"/>
  </xs:complexType>
  <xs:complexType name="checksumInformationType">
    <xs:simpleContent>
      <xs:extension base="xs:string">
        <xs:attribute name="checksumName" type="xfdu:checksumNameType" use="required"/>
      </xs:extension>
    </xs:simpleContent>
  </xs:complexType>
  <xs:complexType name="metadataObjectType">
    <xs:sequence>
      <xs:element name="metadataReference" type="xfdu:metadataReferenceType" minOccurs="0"/>
      <xs:element name="metadataWrap" type="xfdu:metadataWrapType" minOccurs="0"/>
      <xs:element name="dataObjectPointer" type="xfdu:dataObjectPointerType" minOccurs="0"/>
    </xs:sequence>
    <xs:attribute name="ID" use="required">
      <xs:simpleType>
        <xs:restriction base="xs:ID">
          <xs:pattern value="processing"/>
          <xs:pattern value="(a|.+A)cquisitionPeriod"/>
          <xs:pattern value="(p|.+P)latform"/>
          <xs:pattern value=".+Schema"/>
          <xs:pattern value=".+QualityInformation"/>
          <xs:pattern value=".+OrbitReference"/>
          <xs:pattern value=".+GridReference"/>
          <xs:pattern value=".+FrameSet"/>
          <xs:pattern value=".+Index"/>
          <xs:pattern value=".+Annotation"/>
          <xs:pattern value=".+Information"/>
        </xs:restriction>
      </xs:simpleType>
    </xs:attribute>
    <xs:attribute name="classification">
      <xs:simpleType>
        <xs:restriction base="xs:string">
          <xs:enumeration value="DED"/>
          <xs:enumeration value="SYNTAX"/>
          <xs:enumeration value="FIXITY"/>
          <xs:enumeration value="PROVENANCE"/>
          <xs:enumeration value="CONTEXT"/>
          <xs:enumeration value="REFERENCE"/>
          <xs:enumeration value="DESCRIPTION"/>
          <xs:enumeration value="OTHER"/>
        </xs:restriction>
      </xs:simpleType>
    </xs:attribute>
    <xs:attribute name="category">
      <xs:simpleType>
        <xs:restriction base="xs:string">
          <xs:enumeration value="REP"/>
          <xs:enumeration value="PDI"/>
          <xs:enumeration value="DMD"/>
          <xs:enumeration value="OTHER"/>
          <xs:enumeration value="ANY"/>
        </xs:restriction>
      </xs:simpleType>
    </xs:attribute>
  </xs:complexType>
  <xs:complexType name="metadataReferenceType">
    <xs:sequence/>
    <xs:attribute name="href" type="xs:string" use="required"/>
    <xs:attribute name="ID" type="xs:ID"/>
    <xs:attribute name="textInfo" type="xs:string"/>
    <xs:attributeGroup ref="xfdu:LOCATION"/>
    <xs:attribute name="locator" type="xs:string" use="optional" default="/"/>
    <xs:attribute name="vocabularyName" type="xfdu:vocabularyNameType"/>
    <xs:attribute name="mimeType" type="xfdu:mimeTypeType"/>
  </xs:complexType>
  <xs:complexType name="xmlDataType">
    <xs:sequence>
      <xs:any namespace="##any" processContents="lax" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="fileContentType">
    <xs:choice>
      <xs:element name="binaryData" type="xs:base64Binary" minOccurs="0"/>
      <xs:element name="xmlData" type="xfdu:xmlDataType" minOccurs="0"/>
    </xs:choice>
    <xs:attribute name="ID" type="xs:ID"/>
  </xs:complexType>
  <xs:complexType name="metadataWrapType">
    <xs:sequence>
      <xs:element name="xmlData" type="xfdu:xmlDataType"/>
    </xs:sequence>
    <xs:attribute name="mimeType" type="xfdu:mimeTypeType"/>
    <xs:attribute name="textInfo" type="xs:string"/>
    <xs:attribute name="vocabularyName" type="xfdu:vocabularyNameType"/>
  </xs:complexType>
  <xs:complexType name="dataObjectPointerType">
    <xs:attribute name="ID" type="xs:ID"/>
    <xs:attribute name="dataObjectID" use="required" type="xs:IDREF"/>
  </xs:complexType>
  <xs:complexType name="keyDerivationType">
    <xs:attribute name="name" use="required" type="xs:string"/>
    <xs:attribute name="salt" use="required">
      <xs:simpleType>
        <xs:restriction base="xs:string">
          <xs:length value="16"/>
        </xs:restriction>
      </xs:simpleType>
    </xs:attribute>
    <xs:attribute name="iterationCount" use="required" type="xs:long"/>
  </xs:complexType>
  <xs:element name="abstractKeyDerivation" type="xfdu:keyDerivationType" abstract="true"/>
  <xs:element name="keyDerivation" type="xfdu:keyDerivationType" substitutionGroup="xfdu:abstractKeyDerivation"/>
  <xs:complexType name="transformObjectType">
    <xs:sequence>
      <xs:element name="algorithm" type="xs:string"/>
      <xs:element ref="xfdu:abstractKeyDerivation" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    <xs:attribute name="ID" type="xs:ID"/>
    <xs:attribute name="order" type="xs:string"/>
    <xs:attribute name="transformType" use="required">
      <xs:simpleType>
        <xs:restriction base="xs:string">
          <xs:enumeration value="COMPRESSION"/>
          <xs:enumeration value="AUTHENTICATION"/>
          <xs:enumeration value="ENCRYPTION"/>
        </xs:restriction>
      </xs:simpleType>
    </xs:attribute>
  </xs:complexType>
  <xs:complexType name="byteStreamType">
    <xs:sequence>
      <xs:element name="fileLocation" type="xfdu:referenceType"/>
      <xs:element name="checksum" type="xfdu:checksumInformationType"/>
      <!-- start: L0 specific -->
      <xs:element name="byteOrder" minOccurs="0">
        <xs:simpleType>
          <xs:restriction base="xs:string">
            <xs:enumeration value="LITTLE_ENDIAN"/>
            <xs:enumeration value="BIG_ENDIAN"/>
          </xs:restriction>
        </xs:simpleType>
      </xs:element>
      <xs:element name="averageBitRate" type="xs:long" minOccurs="0"/>
      <!-- end: L0 specific -->
    </xs:sequence>
    <xs:attribute name="ID" use="optional" type="xs:ID"/>
    <xs:attribute name="mimeType" type="xfdu:mimeTypeType" use="required"/>
    <xs:attribute name="size" type="xs:long"/>
  </xs:complexType>
  <xs:complexType name="dataObjectType">
    <xs:sequence>
      <xs:element name="byteStream" type="xfdu:byteStreamType" maxOccurs="unbounded"/>
    </xs:sequence>
    <xs:attribute name="ID" type="xs:ID" use="required"/>
    <xs:attribute name="repID" type="xs:IDREFS" use="required"/>
    <xs:attribute name="size" type="xs:long"/>
    <xs:attribute name="combinationName" type="xfdu:combinationMethodType" use="optional"/>
    <xs:attributeGroup ref="xfdu:registrationGroup"/>
  </xs:complexType>
  <xs:complexType name="dataObjectSectionType">
    <xs:sequence>
      <xs:element name="dataObject" type="xfdu:dataObjectType" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="contentUnitType">
    <xs:sequence>
      <xs:element name="dataObjectPointer" type="xfdu:dataObjectPointerType" minOccurs="0"/>
      <xs:element ref="xfdu:abstractContentUnit" minOccurs="0" maxOccurs="unbounded"/>
    </xs:sequence>
    <xs:attribute name="ID" type="xs:ID" use="optional"/>
    <xs:attribute name="order" type="xs:string"/>
    <xs:attribute name="unitType" type="xs:string"/>
    <xs:attribute name="textInfo" type="xs:string"/>
    <xs:attribute name="repID" type="xs:IDREFS"/>
    <xs:attribute name="dmdID" type="xs:IDREFS"/>
    <xs:attribute name="pdiID" type="xs:IDREFS"/>
    <xs:attribute name="anyMdID" type="xs:IDREFS"/>
    <xs:attribute name="behaviorID" type="xs:IDREF"/>
    <xs:anyAttribute namespace="##other" processContents="lax"/>
  </xs:complexType>
  <xs:element name="abstractContentUnit" type="xfdu:contentUnitType" abstract="true"/>
  <xs:element name="contentUnit" type="xfdu:contentUnitType" substitutionGroup="xfdu:abstractContentUnit"/>
  <xs:complexType name="informationPackageMapType">
    <xs:sequence>
      <xs:element ref="xfdu:abstractContentUnit"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="interfaceDefinitionType">
    <xs:complexContent>
      <xs:extension base="xfdu:referenceType">
        <xs:sequence>
          <xs:element name="inputParameter" minOccurs="0" maxOccurs="unbounded">
            <xs:complexType mixed="true">
              <xs:sequence>
                <xs:element name="dataObjectPointer" type="xfdu:dataObjectPointerType" minOccurs="0"/>
              </xs:sequence>
              <xs:attribute name="name" use="required" type="xs:string"/>
              <xs:attribute name="value" type="xs:string"/>
            </xs:complexType>
          </xs:element>
        </xs:sequence>
      </xs:extension>
    </xs:complexContent>
  </xs:complexType>
  <xs:element name="abstractMechanism" type="xfdu:mechanismType" abstract="true"/>
  <xs:complexType name="mechanismType">
    <xs:complexContent>
      <xs:extension base="xfdu:referenceType"/>
    </xs:complexContent>
  </xs:complexType>
  <xs:complexType name="metadataSectionType">
    <xs:sequence>
      <xs:element name="metadataObject" type="xfdu:metadataObjectType" minOccurs="2" maxOccurs="unbounded"/>
    </xs:sequence>
  </xs:complexType>
  <xs:complexType name="XFDUType">
    <xs:sequence>
      <xs:element name="informationPackageMap" type="xfdu:informationPackageMapType"/>
      <xs:element name="metadataSection" type="xfdu:metadataSectionType" minOccurs="0"/>
      <xs:element name="dataObjectSection" type="xfdu:dataObjectSectionType" minOccurs="0"/>
    </xs:sequence>
    <xs:attribute name="version" type="xfdu:versionType" use="required"/>
  </xs:complexType>
  <xs:element name="XFDU" type="xfdu:XFDUType"/>
</xs:schema>
"""


def check_file_against_schema(file, schema):
    cmd = "xmllint --schema '" + schema + "' --noout '" + file + "'"
    cf = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, encoding='utf-8')
    result, resultErr = cf.communicate()
    if cf.returncode != 0:
        report_error("could not verify '" + file + "' against schema '" + schema + "'")
        for line in resultErr.strip().splitlines():
            report_error(line, tags="xmllint")
        return False

    report_message("file '" + file + "' valid according to schema '" + schema + "'")
    return True


def is_xml(file):
    part1, ext = os.path.splitext(file)
    base_name = os.path.basename(file)
    ext = ext.strip()
    if ext.lower() == '.xml' and base_name[0] != ".":
        return True
    else:
        return False


def crc16(filename, crc=0xFFFF):
    if crc16.table is None:
        crc16.table = numpy.empty(256, dtype=numpy.uint16)
        for i in range(256):
            tmp = 0
            if i & 1:
                tmp = tmp ^ 0x1021
            if i & 2:
                tmp = tmp ^ 0x2042
            if i & 4:
                tmp = tmp ^ 0x4084
            if i & 8:
                tmp = tmp ^ 0x8108
            if i & 16:
                tmp = tmp ^ 0x1231
            if i & 32:
                tmp = tmp ^ 0x2462
            if i & 64:
                tmp = tmp ^ 0x48C4
            if i & 128:
                tmp = tmp ^ 0x9188
            crc16.table[i] = tmp
    f = open(filename, 'rb')
    try:
        while True:
            d = f.read(65536)
            if not d:
                break
            for byte in d:
                crc = ((crc << 8) & 0xFF00) ^ crc16.table[((crc >> 8) ^ byte) & 0x00FF]
    finally:
        f.close()
    return crc
crc16.table = None


def md5sum(filename):
    f = open(filename, 'rb')
    m = hashlib.md5()
    try:
        while True:
            d = f.read(65536)
            if not d:
                break
            m.update(d)
    finally:
        f.close()
    return m.hexdigest()


def check_product_crc(product, manifestfile):
    expected_crc = "%04X" % (crc16(manifestfile),)
    actual_crc = os.path.splitext(os.path.basename(product))[0][-4:]
    if expected_crc != actual_crc:
        report_warning("crc in product name '%s' does not match crc of manifest file '%s'" % (actual_crc, expected_crc))
        return False
    return True


def check_manifest_file(file):
    schema = tempfile.NamedTemporaryFile(suffix='.xsd', prefix='manifest-schema-', mode='w')
    try:
        schema.write(manifest_schema)
        schema.file.flush()
        return check_file_against_schema(file, schema.name)
    finally:
        schema.close()
    return False


def verify_safe_product(product):
    has_errors = False
    has_warnings = False

    # remove trailing '/' if it exists
    if product[-1] == '/':
        product = product[:-1]

    global current_product
    current_product = os.path.basename(product)

    if not os.path.exists(product):
        report_error("could not find '%s'" % product)
        return 2

    product = os.path.normpath(product)

    manifestfile = os.path.join(product, "manifest.safe")
    if not os.path.exists(manifestfile):
        report_error("could not find '%s'" % manifestfile)
        return 2

    if os.path.basename(product)[4:7] != "AUX":
        if not check_product_crc(product, manifestfile):
            has_warnings = True

    if not check_manifest_file(manifestfile):
        has_errors = True
    manifest = parse(manifestfile)
    if manifest is None:
        report_error("could not parse xml file '%s'" % manifestfile)
        return 2

    # find list of files in product
    files = []
    for dirpath, dirnames, filenames in os.walk(product):
        files.extend([os.path.join(dirpath, filename) for filename in filenames])
    if manifestfile not in files:
        report_error("could not find 'manifest.safe' in directory listing of product")
        return 2
    files.remove(manifestfile)

    # check files that are referenced in manifest file
    data_objects = {}
    reps = {}

    metadata_section = manifest.find('metadataSection')
    for metadata_object in metadata_section.findall('metadataObject'):
        ID = metadata_object.get('ID')
        if ID[-6:] == "Schema":
            rep_id = ID
            href = metadata_object.find('metadataReference').get('href')
            reps[rep_id] = {'ID': rep_id, 'href': href}
            filepath = os.path.normpath(os.path.join(product, href))
            if filepath in files:
                files.remove(filepath)

    information_package_map = manifest.find('informationPackageMap')
    for content_unit in information_package_map.findall(NSXFDU + 'contentUnit' + '/' + NSXFDU + 'contentUnit'):
        data_object_id = content_unit.find('dataObjectPointer').get('dataObjectID')
        rep_id = content_unit.get('repID')
        # rep_id can be a space separated list of IDs (first one contains the main schema)
        rep_id = rep_id.split()[0]
        if rep_id not in reps:
            report_error("dataObject '" + data_object_id + "' in informationPackageMap contains repID '" + rep_id +
                         "' which is not defined in metadataSection")
            return 2
        data_objects[data_object_id] = {'rep': reps[rep_id]}

    data_object_section = manifest.find('dataObjectSection')
    for data_object in data_object_section.findall('dataObject'):
        data_object_id = data_object.get('ID')
        if data_object_id not in data_objects:
            report_error("dataObject '" + data_object_id +
                         "' in dataObjectSection is not defined in informationPackageMap")
            return 2
        rep_id = data_object.get('repID')
        # rep_id can be a space separated list of IDs (first one contains the main schema)
        rep_id = rep_id.split()[0]
        if data_objects[data_object_id]['rep']['ID'] != rep_id:
            report_error("dataObject '" + data_object_id + "' contains repID '" +
                         data_objects[data_object_id]['rep']['ID'] + "' in informationPackageMap, but '" + rep_id +
                         "' in dataObjectSection")
            has_errors = True
        size = data_object.find('byteStream').get('size')
        href = data_object.find('byteStream/fileLocation').get('href')
        checksum = data_object.find('byteStream/checksum').text
        data_objects[data_object_id]['size'] = size
        data_objects[data_object_id]['href'] = href
        data_objects[data_object_id]['checksum'] = checksum
        filepath = os.path.normpath(os.path.join(product, href))
        if filepath in files:
            files.remove(filepath)

    keys = list(data_objects.keys())
    keys.sort(key=lambda x: data_objects[x]['href'])
    for key in keys:
        data_object = data_objects[key]
        filepath = os.path.normpath(os.path.join(product, data_object['href']))
        # check existence of file
        if not os.path.exists(filepath):
            report_error("manifest.safe reference '" + filepath + "' does not exist")
            has_errors = True
            continue
        # check file size
        filesize = os.path.getsize(filepath)
        if filesize != int(data_object['size']):
            report_error("file size for '" + filepath + "' (" + str(filesize) +
                         ") does not match file size in manifest.safe (" + data_object['size'] + ")")
            has_errors = True
        # check md5sum
        checksum = md5sum(filepath)
        if checksum != data_object['checksum']:
            report_error("checksum for '" + filepath + "' (" + checksum +
                         ") does not match checksum in manifest.safe (" + data_object['checksum'] + ")")
            has_errors = True
        # check with XML Schema (if the file is an xml file)
        if is_xml(filepath) and data_object['rep']:
            schema = os.path.normpath(os.path.join(product, data_object['rep']['href']))
            if not os.path.exists(schema):
                report_error("schema file '" + schema + "' does not exist")
                has_errors = True
                # TODO: remove this temporary workaround
                # try to see if the schema file exists in a 'support' subdirectory
                schema = os.path.normpath(os.path.join(product, "support", data_object['rep']['href']))
                if os.path.exists(schema):
                    report_warning("found schema in 'support' subdirectory - will use that for verification")
                    if not check_file_against_schema(filepath, schema):
                        has_errors = True
            elif not check_file_against_schema(filepath, schema):
                has_errors = True

    # Report on files in the SAFE package that are not referenced by the manifset.safe file
    for file in files:
        report_warning("file '" + file + "' found in product but not included in manifest.safe")
        has_warnings = True

    current_product = None

    if has_errors:
        return 2
    if has_warnings:
        return 3
    return 0


def main():
    args = sys.argv[1:]
    if len(args) == 0:
        print(helptext)
        report_error("invalid arguments")
        sys.exit(1)
    if args[0] == "-h" or args[0] == "--help":
        print(helptext)
        sys.exit()
    if args[0] == "-v" or args[0] == "--version":
        print(versiontext)
        sys.exit()
    if len(args) > 1 and args[0] == "-V":
        global verbose
        verbose = True
        args = args[1:]
    for arg in args:
        if arg[0] == "-":
            print(helptext)
            report_error("invalid arguments")
            sys.exit(1)

    return_code = 0
    for arg in args:
        print(arg)
        result = verify_safe_product(arg)
        if result != 0:
            if result < return_code or return_code == 0:
                return_code = result
        print()
    sys.exit(return_code)


try:
    main()
except SystemExit:
    raise
except:
    report_error(str(sys.exc_info()[1]).replace('\n', ' ').replace('\r', ''), tags="exception")
    sys.exit(1)
