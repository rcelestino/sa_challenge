# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: WidevinePsshData.proto
# Protobuf Python Version: 4.25.3
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x16WidevinePsshData.proto\x12\x0bshaka.media\"\x8f\x02\n\x10WidevinePsshData\x12:\n\talgorithm\x18\x01 \x01(\x0e\x32\'.shaka.media.WidevinePsshData.Algorithm\x12\x0e\n\x06key_id\x18\x02 \x03(\x0c\x12\x10\n\x08provider\x18\x03 \x01(\t\x12\x12\n\ncontent_id\x18\x04 \x01(\x0c\x12\x0e\n\x06policy\x18\x06 \x01(\t\x12\x1b\n\x13\x63rypto_period_index\x18\x07 \x01(\r\x12\x17\n\x0fgrouped_license\x18\x08 \x01(\x0c\x12\x19\n\x11protection_scheme\x18\t \x01(\r\"(\n\tAlgorithm\x12\x0f\n\x0bUNENCRYPTED\x10\x00\x12\n\n\x06\x41\x45SCTR\x10\x01\"G\n\x0eWidevineHeader\x12\x0f\n\x07key_ids\x18\x02 \x03(\t\x12\x10\n\x08provider\x18\x03 \x01(\t\x12\x12\n\ncontent_id\x18\x04 \x01(\x0c')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'WidevinePsshData_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_WIDEVINEPSSHDATA']._serialized_start=40
  _globals['_WIDEVINEPSSHDATA']._serialized_end=311
  _globals['_WIDEVINEPSSHDATA_ALGORITHM']._serialized_start=271
  _globals['_WIDEVINEPSSHDATA_ALGORITHM']._serialized_end=311
  _globals['_WIDEVINEHEADER']._serialized_start=313
  _globals['_WIDEVINEHEADER']._serialized_end=384
# @@protoc_insertion_point(module_scope)
