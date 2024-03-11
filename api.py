from flask import Flask, request, jsonify, make_response
from urllib.parse import parse_qs, urlencode, quote
from mpegdash.parser import MPEGDASHParser
from google.protobuf.message import DecodeError
from google.protobuf.json_format import MessageToDict
from WidevinePsshData_pb2 import WidevinePsshData
import jwt
import datetime
import uuid
import logging
import sys
import traceback
import json
import base64
import struct

app = Flask(__name__)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

SECRET_KEY = "a9ddbcaba8c0ac1a0a812dc0c2f08514b23f2db0a68343cb8199ebb38a6d91e4ebfb378e22ad39c2d01d0b4ec9c34aa91056862ddace3fbbd6852ee60c36acbf"

@app.after_request
def add_cors(response):
    header = response.headers
    header['Access-Control-Allow-Origin'] = '*'
    header['Access-Control-Allow-Methods'] = 'OPTIONS,POST,GET'
    return response

@app.errorhandler(Exception)
def handle_exception(e):
    exception_type, exception_value, exception_traceback = sys.exc_info()
    traceback_string = traceback.format_exception(exception_type, exception_value, exception_traceback)
    err_msg = json.dumps({
        "errorType": exception_type.__name__,
        "errorMessage": str(exception_value),
        "stackTrace": traceback_string
    })
    logger.error(err_msg)        
    return make_response(jsonify({"error_code": 500, "error_message": str(e)}), 500)

@app.route('/token/generate', methods=['GET','POST'])
def generate_token():
    data = request.args.get('data', 'not specified, assestment demo' + str(datetime.datetime.now()))
    key_id = request.args.get('key_id', '')
    payload = {
        'jti': str(uuid.uuid4()),  
        'iat': datetime.datetime.utcnow(),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        'payload': {
            'data': data,
            'key_id': key_id
        }
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS512')
    return make_response(jsonify({"token": token, "urls": {"validate_token": request.url_root + "token/validate?token=" + quote(token), "validate_wvkeyid": request.url_root + "wvkeyid/validate?token=" + quote(token)+"&mpd=" + quote("https://storage.googleapis.com/shaka-demo-assets/sintel-widevine/dash.mpd")}}))

@app.route('/token/validate', methods=['GET','POST'])
def validate_token(nonHttp = False, token = None):
    token = token if token != None else request.args.get('token')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS512'], options={"require": ["iat", "jti"]})
        resp = {"token": token, "valid_token": True, "message": "", "payload": payload}
    except jwt.ExpiredSignatureError as e:
        resp = {"token": token, "valid_token": False, "message": "Signature expired. " + str(e)}
    except jwt.InvalidTokenError as e:
        resp = {"token": token, "valid_token": False, "message": "Invalid token. " + str(e)}
    if nonHttp:
        return resp
    return make_response(jsonify(resp), 401)


@app.route('/wvkeyid/validate', methods=['GET'])
def validate_wvkeyid():
    token = request.args.get('token')
    mpd_url = request.args.get('mpd')
    widevine_scheme_id = "urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"
    
    if not mpd_url:
        return make_response(jsonify({"error": "The mpd (url) parameter is required."}), 400)

    resp = validate_token(True, token)
    if not resp["valid_token"]:
        return make_response(jsonify(resp), 401)

    payload = resp["payload"].get("payload")
    key_id_from_token = payload.get('key_id')
    if not key_id_from_token:
        return make_response(jsonify({"error": "The  key_id field is required in jwt token."}), 400)

    try:
        mpd = MPEGDASHParser.parse(mpd_url)
    except Exception as e:
        return make_response(jsonify({"error": "Failed to download or parse the mpd (url)."}), 500)

    pssh_base64 = None
    for period in mpd.periods:
        for adaptation_set in period.adaptation_sets:
            if adaptation_set.content_protections is not None:
                for content_protection in adaptation_set.content_protections:
                    if content_protection.scheme_id_uri == widevine_scheme_id:
                        if content_protection.pssh:
                            pssh_base64 = content_protection.pssh[0].pssh
                            break
                if pssh_base64:
                    break
        if pssh_base64:
            break
    
    if not pssh_base64:
        return make_response(jsonify({"error": f"No pssh found in the mpd (url) {mpd_url} ."}), 404)
    
    try:
        cenc_pssh_binary = base64.b64decode(pssh_base64)
        cenc_pssh = _parse_pssh(cenc_pssh_binary) 
        widevine_pssh = {}  
        if "pssh_data" in cenc_pssh:
            widevine_pssh = _parse_widevine_data(cenc_pssh["pssh_data"])
            if "key_ids" in widevine_pssh:
                if key_id_from_token in widevine_pssh["key_ids"]:
                    return make_response(jsonify({"valid_key_id": True, "key_id_from_token": key_id_from_token, "verbose": {"pssh_base64": pssh_base64, "cenc_pssh": _serialize_for_json(cenc_pssh), "widevine_pssh": _serialize_for_json(widevine_pssh)}}), 200)    
        return make_response(jsonify({"valid_key_id": False, "key_id_from_token": key_id_from_token, "verbose": {"pssh_base64": pssh_base64, "cenc_pssh": _serialize_for_json(cenc_pssh), "widevine_pssh": _serialize_for_json(widevine_pssh)}}), 401)    
    except DecodeError as e:
        return make_response(jsonify({"error": "Failed to decode pssh." + str(e)}), 500)
    


## Widevine PSSH Tools from Shaka Packager 
## (https://github.com/shaka-project/shaka-packager/blob/5ee2b7f0dedd3e3046f087c734238180c63fe43a/packager/tools/pssh/pssh-box.py#L174)
def _parse_widevine_data(data):
  """Parses Widevine PSSH box from the given binary string."""
  wv = WidevinePsshData()
  wv.ParseFromString(data)

  ret = []
  key_ids = []
  wv_dict = MessageToDict(wv, preserving_proto_field_name=True)
  
  if wv.key_id:
    ret.append('Key IDs (%d):' % len(wv.key_id))
    ret.extend(['  ' + _create_uuid(x) for x in wv.key_id])
    for x in wv.key_id:
      key_ids.append(_create_uuid(x))
  if wv.HasField('provider'):
    ret.append('Provider: ' + wv.provider)
  if wv.HasField('content_id'):
    ret.append('Content ID: ' + base64.b16encode(wv.content_id).decode())
  if wv.HasField('policy'):
    ret.append('Policy: ' + wv.policy)
  if wv.HasField('crypto_period_index'):
    ret.append('Crypto Period Index: %d' % wv.crypto_period_index)
  if wv.HasField('protection_scheme'):
    protection_scheme = struct.pack('>L', wv.protection_scheme)
    ret.append('Protection Scheme: %s' % protection_scheme)

  return {'dump': ret, 'pssh_data': wv_dict, 'key_ids': key_ids}

def _parse_bin_int(data):
    """Parse a binary integer from the data."""
    return int.from_bytes(data, byteorder='big')

def _parse_pssh(pssh_binary):
    offset = 8  # Skip box size and type pssh
    version, flags = pssh_binary[offset], pssh_binary[offset+1:offset+4]
    offset += 4
    
    system_id = pssh_binary[offset:offset+16]
    offset += 16
    
    key_ids = []
    if version == 1:
        key_id_count = _parse_bin_int(pssh_binary[offset:offset+4])
        offset += 4
        for _ in range(key_id_count):
            key_id = pssh_binary[offset:offset+16]
            key_ids.append(key_id)
            offset += 16
            
    pssh_data_length = _parse_bin_int(pssh_binary[offset:offset+4])
    offset += 4
    pssh_data = pssh_binary[offset:offset+pssh_data_length]
    
    return {
        'system_id': system_id,
        'version': version,
        'flags': flags,
        'key_ids': key_ids,
        'pssh_data': pssh_data
    }

def _serialize_for_json(data):
    if isinstance(data, bytes):
        return base64.b64encode(data).decode('utf-8')  
    elif isinstance(data, dict):
        return {k: _serialize_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_serialize_for_json(v) for v in data]
    elif isinstance(data, tuple):
        return tuple(_serialize_for_json(v) for v in data)
    else:
        return data

def _create_uuid(data):
  """Creates a human readable UUID string from the given binary string."""
  ret = base64.b16encode(data).decode().lower()
  return (ret[:8] + '-' + ret[8:12] + '-' + ret[12:16] + '-' + ret[16:20] +
          '-' + ret[20:])

if __name__ == '__main__':
    app.run(debug=True)

