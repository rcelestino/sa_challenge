# Assestment taks

This repo is to submit the assestment task

## Main Features

- **Token Generation**: generate a jwt token with any custom data and and optional key_id field.
- **Token Validation**: validate a given jwt token.
- **WV KeyId Validation**: Validate a WV key_id against the key_id into the token and a specified MPD URL.

### Prerequisites

Before you begin, ensure you have the following tools installed on your system:

- Docker
- Docker-compose
- Make

### Building

To build the api, use the following `make` command, it will crete the proper docker image to run the image:

```sh
make build
```

### Running

To run the API service, use:

```sh
make run
```

This will start the API server, binding it to the port 8080 by default. If this port is already in use on your system, you can modify the docker-compose.yml file or run the command specifying a different port.

## Demo API Endpoints

### Generate Token

- **Endpoint**: `GET /token/generate?data=<data>&key_id=<key_id>`
- **Description**: generate a token with the provided data and keyid.
- **Example**: `http://127.0.0.1:8080/token/generate?data=test_rcelestino_castlab&key_id=f0937e9a-77c8-55f0-a6d4-3864c5d9f365`

### Validate Token

- **Endpoint**: `GET /token/validate?token=<token>`
- **Description**: validates the provided jwt token (signature, claims iat-jti, expiration).
- **Example**: `http://127.0.0.1:8080/token/validate?token=<token>`
- **Note 1**: you can use and click in the urls/validate_token response field of the generate token api

### Validate Widevine Key ID

- **Endpoint**: `GET /wvkeyid/validate?token=<token>&mpd=<mpd_url>`
- **Description**: validates the WV keyId specified in the token against the provided mpd url.
- **Example**: `http://127.0.0.1:8080/wvkeyid/validate?token=<token>&mpd=https://storage.googleapis.com/shaka-demo-assets/sintel-widevine/dash.mpd`
- **Note 1**: you can use and click in the urls/validate_wvkeyid response field of the generate token api
- **Note 2**: it is just parsing the mpd xml to search cenc_pssh fields, it is not parsing the binary mp4 bmff format etc.


