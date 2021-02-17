#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import uuid
import jwt
import time
from unittest.mock import MagicMock


def mocked_requests_post(*args, **kwargs):
    keycloak_url = "https://keycloak.server.url/auth"
    keycloak_auth_realm = "master"
    keycloak_auth_user = "monusername"
    keycloak_auth_password = "monmotdepasse"
    keycloak_auth_client_id = "monclientid"
    keycloak_auth_client_secret = "monclientsecret"

    decoded_access_token = {
        "exp": round(time.time()) + 300,
        "iat": round(time.time()),
        "auth_time": 1589482747,
        "jti": "2a11f9a0-5374-4d7e-a806-28e791327a0b",
        "iss": "{url}/realms/{realm}".format(url=keycloak_url, realm=keycloak_auth_realm),
        "aud": keycloak_auth_client_id,
        "sub": "b605d3a2-e9c8-408e-88e5-1eb9f7694e90",
        "typ": "ID",
        "azp": keycloak_auth_client_id,
        "nonce": "3bK1rDKK39fDclFW-roF3W5-tYe1XiIVkdIVQIqHDx8",
        "session_state": "9d15113c-8d6a-4194-84cd-b5c6c18bee42",
        "acr": "0",
        "email_verified": False,
        "groups": [
            "create-realm",
            "offline_access",
            "admin",
            "uma_authorization",
            "cluster-admin"
        ],
        "preferred_username": keycloak_auth_user
    }
    decoded_refresh_token = {
        "jti": "4a8940b6-49cd-4abd-ac89-aeddbb629878",
        "exp": round(time.time()) + 1800,
        "nbf": 0,
        "iss": "{url}/realms/{realm}".format(url=keycloak_url, realm=keycloak_auth_realm),
        "aud": "{url}/realms/{realm}".format(url=keycloak_url, realm=keycloak_auth_realm),
        "sub": "4dabe12c-e44d-4cc6-bf04-750e7d38b9cb",
        "typ": "Refresh",
        "azp": keycloak_auth_client_id,
        "auth_time": 0,
        "session_state": "76c5f2fe-d95c-4cca-b9ee-f6437492f3be",
        "realm_access": {
            "roles": [
                "offline_access",
                "idm-approvisionnement",
                "uma_authorization"
            ]
        },
        "resource_access": {
            keycloak_auth_client_id: {
                "roles": [
                    "admin"
                ]
            },
            "account": {
                "roles": [
                    "view-profile"
                ]
            }
        },
        "scope": "profile email"
    }
    jwt_secret = 'secret'
    jwt_algo = 'HS256'

    class MockResponse:
        def __init__(self, json_data, status_code):
            self.status_code = status_code
            if json_data is not None:
                self.content = json.dumps(json_data)
            self.headers = {
                "dict": {
                    "connection": "close",
                    "content-type": "application/json;charset=UTF-8",
                    "date": "Wed, 30 Oct 2019 12:46:02 GMT",
                    "transfer-encoding": "chunked"},
                "headers": [
                    'Content-Type: application/json;charset=UTF-8\r\n',
                    'Transfer-Encoding: chunked\r\n',
                    'Date: Wed, 30 Oct 2019 12:46:02 GMT\r\n',
                    'Connection: close\r\n']}

        def read(self):
            return self.content

    if kwargs["url"] == "{url}/realms/{realm}/protocol/openid-connect/token".format(
            url=keycloak_url, realm=keycloak_auth_realm):
        access_token = jwt.encode(
            decoded_access_token,
            jwt_secret,
            algorithm=jwt_algo,
            headers={
                'kid': 'NWBeViRdZb3-n0pBGu5YMJnaV1UMRMLjcvMOPJA2Gko',
                'alg': jwt_algo,
                'typ': 'jwt'})
        refresh_token = jwt.encode(
            decoded_refresh_token,
            jwt_secret,
            algorithm=jwt_algo,
            headers={
                'kid': 'db1c7a43-58fb-421b-828c-98a921eae51d',
                'alg': jwt_algo,
                'typ': 'jwt'})
        content = {}
        content["access_token"] = access_token
        content["expires_in"] = 300
        content["refresh_expires_in"] = 1800
        content["refresh_token"] = refresh_token
        content["token_type"] = 'bearer'
        content["not-before-policy"] = 0
        content["session_state"] = str(uuid.uuid1())
        content["scope"] = "profile email"
        response = MockResponse(content, 200)
        return response

    return MockResponse(None, 404)


def mocked_open_url(*args, **kwargs):
    keycloak_url = "https://keycloak.server.url/auth"
    keycloak_auth_realm = "master"
    keycloak_auth_user = "monusername"
    keycloak_auth_password = "monmotdepasse"
    keycloak_auth_client_id = "monclientid"
    keycloak_auth_client_secret = "monclientsecret"

    decoded_access_token = {
        "exp": round(time.time()) + 300,
        "iat": round(time.time()),
        "auth_time": 1589482747,
        "jti": "2a11f9a0-5374-4d7e-a806-28e791327a0b",
        "iss": "{url}/realms/{realm}".format(url=keycloak_url, realm=keycloak_auth_realm),
        "aud": keycloak_auth_client_id,
        "sub": "b605d3a2-e9c8-408e-88e5-1eb9f7694e90",
        "typ": "ID",
        "azp": keycloak_auth_client_id,
        "nonce": "3bK1rDKK39fDclFW-roF3W5-tYe1XiIVkdIVQIqHDx8",
        "session_state": "9d15113c-8d6a-4194-84cd-b5c6c18bee42",
        "acr": "0",
        "email_verified": False,
        "groups": [
            "create-realm",
            "offline_access",
            "admin",
            "uma_authorization",
            "cluster-admin"
        ],
        "preferred_username": keycloak_auth_user
    }
    decoded_refresh_token = {
        "jti": "4a8940b6-49cd-4abd-ac89-aeddbb629878",
        "exp": round(time.time()) + 1800,
        "nbf": 0,
        "iss": "{url}/realms/{realm}".format(url=keycloak_url, realm=keycloak_auth_realm),
        "aud": "{url}/realms/{realm}".format(url=keycloak_url, realm=keycloak_auth_realm),
        "sub": "4dabe12c-e44d-4cc6-bf04-750e7d38b9cb",
        "typ": "Refresh",
        "azp": keycloak_auth_client_id,
        "auth_time": 0,
        "session_state": "76c5f2fe-d95c-4cca-b9ee-f6437492f3be",
        "realm_access": {
            "roles": [
                "offline_access",
                "idm-approvisionnement",
                "uma_authorization"
            ]
        },
        "resource_access": {
            keycloak_auth_client_id: {
                "roles": [
                    "admin"
                ]
            },
            "account": {
                "roles": [
                    "view-profile"
                ]
            }
        },
        "scope": "profile email"
    }
    jwt_secret = 'secret'
    jwt_algo = 'HS256'

    class MockResponse:
        def __init__(self, json_data, status_code):
            self.status_code = status_code
            if json_data is not None:
                self.content = json.dumps(json_data)
            self.headers = {
                "dict": {
                    "connection": "close",
                    "content-type": "application/json;charset=UTF-8",
                    "date": "Wed, 30 Oct 2019 12:46:02 GMT",
                    "transfer-encoding": "chunked"},
                "headers": [
                    'Content-Type: application/json;charset=UTF-8\r\n',
                    'Transfer-Encoding: chunked\r\n',
                    'Date: Wed, 30 Oct 2019 12:46:02 GMT\r\n',
                    'Connection: close\r\n']}

        def read(self):
            return self.content

    if args[0] == "{url}/realms/{realm}/protocol/openid-connect/token".format(
            url=keycloak_url, realm=keycloak_auth_realm) and kwargs["method"] == 'POST':
        access_token = jwt.encode(
            decoded_access_token,
            jwt_secret,
            algorithm=jwt_algo,
            headers={
                'kid': 'NWBeViRdZb3-n0pBGu5YMJnaV1UMRMLjcvMOPJA2Gko',
                'alg': jwt_algo,
                'typ': 'jwt'})
        refresh_token = jwt.encode(
            decoded_refresh_token,
            jwt_secret,
            algorithm=jwt_algo,
            headers={
                'kid': 'db1c7a43-58fb-421b-828c-98a921eae51d',
                'alg': jwt_algo,
                'typ': 'jwt'})
        content = {}
        content["access_token"] = access_token.decode()
        content["expires_in"] = 300
        content["refresh_expires_in"] = 1800
        content["refresh_token"] = refresh_token.decode()
        content["token_type"] = 'bearer'
        content["not-before-policy"] = 0
        content["session_state"] = str(uuid.uuid1())
        content["scope"] = "profile email"
        response = MockResponse(str(content), 200)
        return content

    return MockResponse(None, 404)


def mock_json_load(*args, **kwargs):
    return args[0]
