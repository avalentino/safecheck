#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
# Copyright (C) 2011-2012 S[&]T, The Netherlands.
# Copyright (C) 2022 Antonio Valentino.

"""Perform constency checks on SAFE products.

Check the contents of the SAFE products against information included in
the manifest file, and also perform checks on the components size and
checksums.

All XML files included in the product are checked against their schema
(if available).

Additional checks on consistency between the product name and information
included in the mnifest file are also performed.
"""

import io
import os
import sys
import hashlib
import logging
import pathlib
import argparse
import binascii
import functools
from typing import IO, Iterator, Optional, Union

from lxml import etree


__version__ = '3.0'
_log = logging.getLogger(__name__)


EX_OK = getattr(os, "EX_OK", 0)
EX_FAILURE = 1
EX_ERROR = 2
EX_WARNING = 3
EX_INTERRUPT = 130


NSXFDU = "{urn:ccsds:schema:xfdu:1}"


MANIFEST_SCHEMA_STR = """\
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


def is_xml(filename: os.PathLike) -> bool:
    """Return True if the filename is an XML file."""
    filename = pathlib.Path(filename)
    return filename.suffix.lower() == '.xml' and filename.name[0] != "."


def crc16(data: bytes, crc: int = 0xFFFF) -> bytes:
    """Compute CRC-16 incrementally."""
    return binascii.crc_hqx(data, crc)


def blockiter(fd: IO, blocksize: int = io.DEFAULT_BUFFER_SIZE) -> Iterator:
    """Iterate on file-like objects reading blocks of the specified size.

    The `fd` parameter must be a binary or text file-like object opened
    for reading.
    The `blocksize` parameter defaults to `io.DEFAULT_BUFFER_SIZE`.
    """
    guard = '' if isinstance(fd, io.TextIOBase) else b''
    return iter(functools.partial(fd.read, blocksize), guard)


def get_md5sum(filename: os.PathLike) -> str:
    """Retuen the MD% checksum of the specified file."""
    md5 = hashlib.md5()
    with open(filename, 'rb') as fd:
        for data in blockiter(fd):
            md5.update(data)
    return md5.hexdigest()


XmlSchemaType = Union[os.PathLike, etree.XMLSchema]


def check_file_against_schema(xmlfile: os.PathLike,
                              schema: XmlSchemaType) -> bool:
    """Validate the input XML file aganst the provided schema."""
    xmldoc = etree.parse(os.fspath(xmlfile))

    if not isinstance(schema, etree.XMLSchema):
        schemafile = schema
        schemadoc = etree.parse(os.fspath(schemafile))
        schema = etree.XMLSchema(schemadoc.getroot())
    else:
        schemafile = "basic manifest schema (internal)"

    try:
        schema.assertValid(xmldoc)
    except etree.DocumentInvalid as exc:
        _log.error(
            f"could not verify '{xmlfile}' against schema '{schemafile}'")
        for error in exc.error_log:
            _log.error(f"{error.filename}:{error.line}: {error.message}")
        _log.error(f"{xmlfile} fails to validate")

    _log.info(f"file '{xmlfile}' valid according to schema '{schemafile}'")
    return True


def check_manifest_file(filename: os.PathLike,
                        schema: Optional[os.PathLike] = None) -> bool:
    """Check id the manifest file is valid according to the provided schema."""
    if schema is None:
        schemadoc = etree.fromstring(MANIFEST_SCHEMA_STR)
        schema = etree.XMLSchema(schemadoc)
    return check_file_against_schema(filename, schema)


def check_product_crc(product: os.PathLike, manifestfile: os.PathLike) -> bool:
    """Check the crc16 checksum of the manifest file.
    
    Check if the crc16 checksum of the manifest file is consistent with
    the one included in the product name.
    """
    product = pathlib.Path(product)
    manifestfile = pathlib.Path(manifestfile)

    expected_crc = crc16(manifestfile.read_bytes())
    expected_crc = format(expected_crc, '04X')
    actual_crc = product.stem[-4:]
    if expected_crc != actual_crc:
        _log.warning(
            f"crc in product name '{actual_crc}' does not match crc "
            f"of manifest file '{expected_crc}'"
        )
        return False
    return True


def verify_safe_product(product: os.PathLike) -> int:
    """Perform consistency checks of a SAVE products."""
    has_errors = False
    has_warnings = False

    if not pathlib.Path(product).exists():
        _log.error(f"could not find '{product}'")
        return EX_ERROR

    product = pathlib.Path(product).resolve()

    manifestfile = product / "manifest.safe"
    if not manifestfile.exists():
        _log.error(f"could not find '{manifestfile}'")
        return EX_ERROR

    if product.name[4:7] != "AUX":
        if not check_product_crc(product, manifestfile):
            has_warnings = True

    if not check_manifest_file(manifestfile):
        has_errors = True
    manifest_xmldoc = etree.parse(os.fspath(manifestfile))
    if manifest_xmldoc is None:
        _log.error(f"could not parse xml file '{manifestfile}'")
        return EX_ERROR

    # find list of files in product
    files = {item for item in product.rglob("*") if item.is_file()}
    if manifestfile not in files:
        _log.error(
            "could not find 'manifest.safe' in directory listing of product")
        return EX_ERROR
    files.remove(manifestfile)

    # check files that are referenced in manifest file
    data_objects = {}
    reps = {}

    metadata_section = manifest_xmldoc.find('metadataSection')
    for metadata_object in metadata_section.findall('metadataObject'):
        elem_id = metadata_object.get('ID')
        if elem_id.endswith("Schema"):
            rep_id = elem_id
            href = metadata_object.find('metadataReference').get('href')
            reps[rep_id] = {'ID': rep_id, 'href': href}
            filepath = product / href
            if filepath in files:
                files.remove(filepath)

    information_package_map = manifest_xmldoc.find('informationPackageMap')
    xp = f"{NSXFDU}contentUnit/{NSXFDU}contentUnit"
    for content_unit in information_package_map.findall(xp):
        data_object = content_unit.find('dataObjectPointer')
        data_object_id = data_object.get('dataObjectID')
        rep_id = content_unit.get('repID')
        # rep_id can be a space separated list of IDs
        # (first one contains the main schema)
        rep_id = rep_id.split()[0]
        if rep_id not in reps:
            _log.error(
                f"dataObject '{data_object_id}' in informationPackageMap "
                f"contains repID '{rep_id}' which is not defined in "
                f"metadataSection")
            return EX_ERROR
        data_objects[data_object_id] = {'rep': reps[rep_id]}

    data_object_section = manifest_xmldoc.find('dataObjectSection')
    for data_object in data_object_section.findall('dataObject'):
        data_object_id = data_object.get('ID')
        if data_object_id not in data_objects:
            _log.error(
                f"dataObject '{data_object_id}' in dataObjectSection is "
                f"not defined in informationPackageMap")
            return EX_ERROR
        rep_id = data_object.get('repID')
        # rep_id can be a space separated list of IDs
        # (first one contains the main schema)
        rep_id = rep_id.split()[0]
        if data_objects[data_object_id]['rep']['ID'] != rep_id:
            _log.error(
                f"dataObject '{data_object_id}' contains repID "
                f"'{data_objects[data_object_id]['rep']['ID']}' in "
                f"informationPackageMap, but '{rep_id}' in dataObjectSection")
            has_errors = True
        size = data_object.find('byteStream').get('size')
        href = data_object.find('byteStream/fileLocation').get('href')
        checksum = data_object.find('byteStream/checksum').text
        data_objects[data_object_id]['size'] = size
        data_objects[data_object_id]['href'] = href
        data_objects[data_object_id]['checksum'] = checksum
        filepath = product / href
        if filepath in files:
            files.remove(filepath)

    keys = list(data_objects.keys())
    keys.sort(key=lambda x: data_objects[x]['href'])
    for key in keys:
        data_object = data_objects[key]
        filepath = product / data_object['href']
        # check existence of file
        if not filepath.exists():
            _log.error(f"manifest.safe reference '{filepath}' does not exist")
            has_errors = True
            continue
        # check file size
        filesize = filepath.stat().st_size
        if filesize != int(data_object['size']):
            _log.error(
                f"file size for '{filepath}' ({filesize}) does not match "
                f"file size in manifest.safe ({data_object['size']})")
            has_errors = True
        # check md5sum
        checksum = get_md5sum(filepath)
        if checksum != data_object['checksum']:
            _log.error(
                f"checksum for '{filepath}' ({checksum}) does not match "
                f"checksum in manifest.safe ({data_object['checksum']})")
            has_errors = True
        # check with XML Schema (if the file is an xml file)
        if is_xml(filepath) and data_object['rep']:
            schema = product / data_object['rep']['href']
            if not schema.exists():
                _log.error(f"schema file '{schema}' does not exist")
                has_errors = True
                # TODO: remove this temporary workaround
                # try to see if the schema file exists in a 'support'
                # subdirectory
                schema = product / "support" / data_object['rep']['href']
                if schema.exists():
                    _log.warning(
                        "found schema in 'support' subdirectory - "
                        "will use that for verification")
                    if not check_file_against_schema(filepath, schema):
                        has_errors = True
            elif not check_file_against_schema(filepath, schema):
                has_errors = True

    # Report on files in the SAFE package that are not referenced by the
    # manifset.safe file
    for filename in sorted(files):
        _log.warning(
            f"file '{filename}' found in product but not included "
            f"in manifest.safe")
        has_warnings = True

    # TODO: add consistency checks against the product name

    if has_errors:
        return EX_ERROR
    if has_warnings:
        return EX_WARNING
    return EX_OK


# --- CLI ---------------------------------------------------------------------
PROG = 'safechecl'
LOGFMT = '%(levelname)s: %(message)s'


def _autocomplete(parser):
    try:
        import argcomplete
    except ImportError:
        pass
    else:
        argcomplete.autocomplete(parser)


def _set_logging_control_args(parser, default_loglevel='WARNING'):
    """Setup command line options for logging control."""
    loglevels = [logging.getLevelName(level) for level in range(10, 60, 10)]

    parser.add_argument(
        '--loglevel', default=default_loglevel, choices=loglevels,
        help='logging level (default: %(default)s)')
    parser.add_argument(
        '-q', '--quiet', dest='loglevel', action='store_const',
        const='ERROR',
        help='suppress standard output messages, '
             'only errors are printed to screen')
    parser.add_argument(
        '-v', '--verbose', dest='loglevel', action='store_const',
        const='INFO', help='print verbose output messages')
    parser.add_argument(
        '-d', '--debug', dest='loglevel', action='store_const',
        const='DEBUG', help='print debug messages')

    return parser


def get_parser(subparsers=None):
    """Instantiate the command line argument (sub-)parser."""
    name = PROG
    synopsis = __doc__.splitlines()[0]
    doc = __doc__

    if subparsers is None:
        parser = argparse.ArgumentParser(prog=name, description=doc)
        parser.add_argument(
            '--version', action='version', version='%(prog)s v' + __version__)
    else:
        parser = subparsers.add_parser(name, description=doc, help=synopsis)

    parser = _set_logging_control_args(parser)

    # Command line options
    # ...

    # Positional arguments
    parser.add_argument('products', nargs="+", metavar="SAFE-PRODUCT")

    if subparsers is None:
        _autocomplete(parser)

    return parser


def parse_args(args=None, namespace=None, parser=None):
    """Parse command line arguments."""
    if parser is None:
        parser = get_parser()

    args = parser.parse_args(args, namespace)

    return args


def main(*argv):
    """Main CLI interface."""
    # setup logging
    logging.basicConfig(format=LOGFMT, stream=sys.stdout)
    logging.captureWarnings(True)

    # parse cmd line arguments
    args = parse_args(argv if argv else None)

    # execute main tasks
    exit_code = EX_OK
    try:
        logging.getLogger().setLevel(args.loglevel)

        for product in args.products:
            print(product)
            result = verify_safe_product(product)
            if result != 0:
                if result < exit_code or exit_code == EX_OK:
                    exit_code = result
            print()

    except Exception as exc:
        _log.critical(
            'unexpected exception caught: {!r} {}'.format(
                type(exc).__name__, exc))
        _log.debug('stacktrace:', exc_info=True)
        exit_code = EX_FAILURE
    except KeyboardInterrupt:
        _log.warning('Keyboard interrupt received: exit the program')
        exit_code = EX_INTERRUPT

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
