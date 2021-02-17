#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest import TestCase, mock
from plugins.module_utils.keycloak import get_token, get_service_account_token, KeycloakAPI, \
    isDictEquals, remove_arguments_with_value_none, ClientScope, ProtocolMapper
from tests.unit.module_utils.mock_keycloak_server import mocked_open_url, mock_json_load

import jwt


class KeycloakTestCase(TestCase):

    keycloak_url = "https://keycloak.server.url/auth"
    keycloak_auth_realm = "master"
    keycloak_auth_user = "monusername"
    keycloak_auth_password = "monmotdepasse"
    keycloak_auth_client_id = "monclientid"
    keycloak_auth_client_secret = "monclientsecret"
    jwt_secret = 'secret'
    jwt_algo = 'HS256'
    validate_certs = False

    @mock.patch('plugins.module_utils.keycloak.open_url',
                side_effect=mocked_open_url)
    @mock.patch('plugins.module_utils.keycloak.json.load',
                side_effect=mock_json_load)
    def testObtenirUnAccessTokenValide(self, mocked_open_url, mock_json_load):
        authorization_header = get_token(
            base_url=self.keycloak_url,
            auth_realm=self.keycloak_auth_realm,
            client_id=self.keycloak_auth_client_id,
            auth_username=self.keycloak_auth_user,
            auth_password=self.keycloak_auth_password,
            client_secret=self.keycloak_auth_client_secret,
            validate_certs=self.validate_certs)
        access_token = authorization_header['Authorization'].split(' ')[1]
        decoded_access_token = jwt.decode(
            access_token, self.jwt_secret, algorithms=[
                self.jwt_algo], verify=False)
        self.assertEqual(
            decoded_access_token["preferred_username"],
            self.keycloak_auth_user,
            "L'utilisateur authentifié n'est pas le bon: {0}".format(
                decoded_access_token["preferred_username"]))

    @mock.patch('plugins.module_utils.keycloak.open_url',
                side_effect=mocked_open_url)
    @mock.patch('plugins.module_utils.keycloak.json.load',
                side_effect=mock_json_load)
    def testObtenirUnAccessTokenValideAvecUnComteDeService(
            self, mocked_open_url, mock_json_load):
        authorization_header = get_service_account_token(
            base_url=self.keycloak_url,
            auth_realm=self.keycloak_auth_realm,
            client_id=self.keycloak_auth_client_id,
            client_secret=self.keycloak_auth_client_secret,
            validate_certs=self.validate_certs)
        access_token = authorization_header['Authorization'].split(' ')[1]
        decoded_access_token = jwt.decode(
            access_token, self.jwt_secret, algorithms=[
                self.jwt_algo], verify=False)
        self.assertEqual(
            decoded_access_token["preferred_username"],
            self.keycloak_auth_user,
            "L'utilisateur authentifié n'est pas le bon: {0}".format(
                decoded_access_token["preferred_username"]))

    @mock.patch('plugins.module_utils.keycloak.open_url',
                side_effect=mocked_open_url)
    @mock.patch('plugins.module_utils.keycloak.json.load',
                side_effect=mock_json_load)
    def testCreerUnObjetKeycloakAvecToken(
            self, mocked_open_url, mock_json_load):
        kc = KeycloakAPI(auth_keycloak_url=self.keycloak_url,
                         auth_client_id=self.keycloak_auth_client_id,
                         auth_username=self.keycloak_auth_user,
                         auth_password=self.keycloak_auth_password,
                         auth_realm=self.keycloak_auth_realm,
                         auth_client_secret=self.keycloak_auth_client_secret,
                         validate_certs=self.validate_certs)
        access_token = kc.restheaders['Authorization'].split(' ')[1]
        decoded_access_token = jwt.decode(
            access_token, self.jwt_secret, algorithms=[
                self.jwt_algo], verify=False)
        self.assertEqual(
            decoded_access_token["preferred_username"],
            self.keycloak_auth_user,
            "L'utilisateur authentifié n'est pas le bon: {0}".format(
                decoded_access_token["preferred_username"]))


class KeycloakIsDictEqualsTestCase(TestCase):
    dict1 = dict(
        test1='test1',
        test2=dict(
            test1='test1',
            test2='test2'
        ),
        test3=['test1', dict(test='test1', test2='test2')]
    )
    dict2 = dict(
        test1='test1',
        test2=dict(
            test1='test1',
            test2='test2',
            test3='test3'
        ),
        test3=['test1', dict(test='test1', test2='test2'), 'test3'],
        test4='test4'
    )
    dict3 = dict(
        test1='test1',
        test2=dict(
            test1='test1',
            test2='test23',
            test3='test3'
        ),
        test3=['test1', dict(test='test1', test2='test23'), 'test3'],
        test4='test4'
    )

    dict5 = dict(
        test1='test1',
        test2=dict(
            test1=True,
            test2='test23',
            test3='test3'
        ),
        test3=['test1', dict(test='test1', test2='test23'), 'test3'],
        test4='test4'
    )

    dict6 = dict(
        test1='test1',
        test2=dict(
            test1='true',
            test2='test23',
            test3='test3'
        ),
        test3=['test1', dict(test='test1', test2='test23'), 'test3'],
        test4='test4'
    )
    dict7 = [{'roles': ['view-clients',
                        'view-identity-providers',
                        'view-users',
                        'query-realms',
                        'manage-users'],
              'clientid': 'master-realm'},
             {'roles': ['manage-account',
                        'view-profile',
                        'manage-account-links'],
              'clientid': 'account'}]
    dict8 = [{'roles': ['view-clients',
                        'query-realms',
                        'view-users'],
              'clientid': 'master-realm'},
             {'roles': ['manage-account-links',
                        'view-profile',
                        'manage-account'],
              'clientid': 'account'}]

    def test_trivial(self):
        self.assertTrue(isDictEquals(self.dict1, self.dict1))

    def test_equals_with_dict2_bigger_than_dict1(self):
        self.assertTrue(isDictEquals(self.dict1, self.dict2))

    def test_not_equals_with_dict2_bigger_than_dict1(self):
        self.assertFalse(isDictEquals(self.dict2, self.dict1))

    def test_not_equals_with_dict1_different_than_dict3(self):
        self.assertFalse(isDictEquals(self.dict1, self.dict3))

    def test_equals_with_dict5_contain_bool_and_dict6_contain_true_string(
            self):
        self.assertFalse(isDictEquals(self.dict5, self.dict6))
        self.assertFalse(isDictEquals(self.dict6, self.dict5))

    def test_not_equals_dict7_dict8_compare_dict7_with_list_bigger_than_dict8_but_reverse_equals(
            self):
        self.assertFalse(isDictEquals(self.dict7, self.dict8))
        self.assertTrue(isDictEquals(self.dict8, self.dict7))


class KeycloakRemoveNoneValuesFromDictTest(TestCase):
    test1 = {
        "key1": "value1",
        "key2": None
    }
    expected1 = {
        "key1": "value1"
    }
    test2 = {
        "key1": "value1",
        "list1": [{
            "list1key1": None,
            "list1key2": "list1value2"
        }
        ]
    }
    expected2 = {
        "key1": "value1",
        "list1": [{
            "list1key2": "list1value2"
        }
        ]
    }
    test3 = {
        "key1": "value1",
        "list1": [{
            "list1key1": None,
            "list1key2": "list1value2",
            "list1list1": [{
                "list1list1key1": "list1list1value1",
                "list1list1key2": None
            }]
        },
            "list1value1",
            None
        ],
        "dict1": {
            "dict1key1": "dict1value1",
            "dict1key2": None,
            "dict1dict1": [{
                "dict1dict1key1": None,
                "dict1dict1key2": "dict1dict1Value2"
            }]
        }
    }
    expected3 = {
        "key1": "value1",
        "list1": [{
            "list1key2": "list1value2",
            "list1list1": [{
                "list1list1key1": "list1list1value1"
            }]
        },
            "list1value1",
        ],
        "dict1": {
            "dict1key1": "dict1value1",
            "dict1dict1": [{
                "dict1dict1key2": "dict1dict1Value2"
            }]
        }
    }

    def testSimpleDictWithOneNoneValue(self):
        result1 = remove_arguments_with_value_none(self.test1)
        self.assertDictEqual(result1, self.expected1, str(result1))

    def testDictWithListContainingOneNoneValue(self):
        result2 = remove_arguments_with_value_none(self.test2)
        self.assertDictEqual(result2, self.expected2, str(result2))

    def testDictWithListAndDictThreeLevel(self):
        result3 = remove_arguments_with_value_none(self.test3)
        self.assertDictEqual(result3, self.expected3, str(result3))


class ClientScopeRepresentationTestCase(TestCase):
    clientScopeTest = {
        "id": "4657a25e-9db1-40b5-a1f2-c3634f79c3f2",
        "name": "kube-lacave-audience",
        "description": "Scope pour Kubernetes",
        "protocol": "openid-connect",
        "attributes": {
            "include.in.token.scope": "true",
            "display.on.consent.screen": "true"
        },
        "protocolMappers": [
            {
                "id": "fb27cacd-6f5d-4cc6-b7af-9b2c2e8a0da5",
                "name": "kube-lacave-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": "false",
                "config": {
                    "included.client.audience": "kubelacave",
                    "id.token.claim": "true",
                    "access.token.claim": "true"
                }
            }
        ]
    }

    def test_GetClientScopeFromRepresentation(self):
        scope = ClientScope(rep=self.clientScopeTest)
        self.assertEqual(
            scope.id,
            self.clientScopeTest['id'],
            "Incorrect client scope id. {0} != {1}".format(
                scope.id,
                self.clientScopeTest['id']))
        self.assertEqual(
            scope.name,
            self.clientScopeTest['name'],
            "Incorrect client scope name. {0} != {1}".format(
                scope.name,
                self.clientScopeTest['name']))
        self.assertEqual(
            scope.description,
            self.clientScopeTest['description'],
            "Incorrect client scope description. {0} != {1}".format(
                scope.description,
                self.clientScopeTest['description']))
        self.assertEqual(
            scope.protocol,
            self.clientScopeTest['protocol'],
            "Incorrect client scope protocol. {0} != {1}".format(
                scope.protocol,
                self.clientScopeTest['protocol']))
        self.assertEqual(scope.attributes,
                         self.clientScopeTest['attributes'],
                         "Incorrect client scope attributes. {0} != {1}".format(str(scope.attributes),
                                                                                str(self.clientScopeTest['attributes'])))

    def test_NewClientScopeFromModule(self):
        module_params = {
            'auth_keycloak_url': 'http://localhost:8080/auth',
            'auth_sername': 'admin',
            'auth_password': 'password',
            'auth_realm': 'master',
            'realm': 'master',
            'name': 'testclientscope',
            'description': 'Client scope',
            'protocol': 'openid-connect',
            'attributes': {
                'include.in.token.scope': 'true',
                'display.on.consent.screen': 'true'
            },
            'protocolMappers': [
                {
                    'name': 'test-audience',
                    'protocol': 'openid-connect',
                    'protocolMapper': 'oidc-audience-mapper',
                    'consentRequired': 'false',
                    'config': {
                        'included.client.audience': 'admin-cli',
                        'id.token.claim': 'true'
                    },
                    'access.token.claim': 'true'
                }
            ],
            'state': 'present'
        }

        scope = ClientScope(module_params=module_params)
        self.assertEqual(
            scope.name,
            module_params['name'],
            "Incorrect client scope name. {0} != {1}".format(
                scope.name,
                module_params['name']))
        self.assertEqual(
            scope.description,
            module_params['description'],
            "Incorrect client scope description. {0} != {1}".format(
                scope.description,
                module_params['description']))
        self.assertEqual(
            scope.protocol,
            module_params['protocol'],
            "Incorrect client scope protocol. {0} != {1}".format(
                scope.protocol,
                module_params['protocol']))
        self.assertEqual(scope.attributes,
                         module_params['attributes'],
                         "Incorrect client scope attributes. {0} != {1}".format(str(scope.attributes),
                                                                                str(module_params['attributes'])))
        self.assertTrue(
            isDictEquals(
                scope.protocolMappers[0].getRepresentation(),
                module_params['protocolMappers'][0]),
            "Incorrect client scope protocolMappers. {0} != {1}".format(
                str(
                    scope.protocolMappers[0].getRepresentation()),
                str(
                    module_params['protocolMappers'][0])))

    def test_NewClientScopeFromRepresentation(self):
        scope = ClientScope(rep=self.clientScopeTest)
        rep = scope.getRepresentation()
        self.assertEquals(
            rep, self.clientScopeTest, "{0} is not {1}".format(
                str(rep), str(
                    self.clientScopeTest)))

    def test_GetProtocolMapperFromRepresentation(self):
        mapper = ProtocolMapper(rep=self.clientScopeTest['protocolMappers'][0])
        self.assertEqual(
            mapper.id,
            self.clientScopeTest['protocolMappers'][0]['id'],
            "Incorrect protocol mapper id. {0} != {1}".format(
                mapper.id,
                self.clientScopeTest['protocolMappers'][0]['id']))
        self.assertEqual(
            mapper.name,
            self.clientScopeTest['protocolMappers'][0]['name'],
            "Incorrect protocol mapper name. {0} != {1}".format(
                mapper.name,
                self.clientScopeTest['protocolMappers'][0]['name']))
        self.assertEqual(
            mapper.protocol,
            self.clientScopeTest['protocolMappers'][0]['protocol'],
            "Incorrect protocol mapper protocol. {0} != {1}".format(
                mapper.protocol,
                self.clientScopeTest['protocolMappers'][0]['protocol']))
        self.assertEqual(
            mapper.protocolMapper,
            self.clientScopeTest['protocolMappers'][0]['protocolMapper'],
            "Incorrect protocol mapper protocolMapper. {0} != {1}".format(
                mapper.protocolMapper,
                self.clientScopeTest['protocolMappers'][0]['protocolMapper']))
        self.assertEqual(
            mapper.consentRequired,
            self.clientScopeTest['protocolMappers'][0]['consentRequired'],
            "Incorrect protocol mapper consentRequired. {0} != {1}".format(
                mapper.consentRequired,
                self.clientScopeTest['protocolMappers'][0]['consentRequired']))
        self.assertEqual(mapper.config,
                         self.clientScopeTest['protocolMappers'][0]['config'],
                         "Incorrect protocol mapper config. {0} != {1}".format(str(mapper.config),
                                                                               str(self.clientScopeTest['protocolMappers'][0]['config'])))

    def test_CompareSameClientScopeChangedIsFalse(self):
        scope = ClientScope(rep=self.clientScopeTest)
        scope_2 = ClientScope(rep=self.clientScopeTest)
        self.assertFalse(
            scope.need_change(scope_2),
            "Scope changed but not supposed to")

    def test_CompareSameClientScopeWithoutIdsChangedIsFalse(self):
        scoperep = {'name': 'newclientscope',
                    'description': 'New Client Scope',
                    'protocol': 'openid-connect',
                    'attributes': {'include.in.token.scope': 'true',
                                   'display.on.consent.screen': 'true'},
                    'protocolMappers': [{'name': 'new-mapper-audience',
                                         'protocol': 'openid-connect',
                                         'protocolMapper': 'oidc-audience-mapper',
                                         'consentRequired': False,
                                         'config': {'included.client.audience': 'test',
                                                    'id.token.claim': 'true',
                                                    'access.token.claim': 'true'}}]}
        scope = ClientScope(rep=scoperep)
        scoperep = {
            'id': '7e566f2c-6485-4a30-89f3-45ebb82e06eb',
            'name': 'newclientscope',
            'description': 'New Client Scope',
            'protocol': 'openid-connect',
            'attributes': {
                'include.in.token.scope': 'true',
                'display.on.consent.screen': 'true'},
            'protocolMappers': [
                {
                    'id': 'c0637c21-c2ab-4abc-941d-63fbd71e8527',
                    'name': 'new-mapper-audience',
                    'protocol': 'openid-connect',
                    'protocolMapper': 'oidc-audience-mapper',
                    'consentRequired': False,
                    'config': {
                        'included.client.audience': 'test',
                        'id.token.claim': 'true',
                        'access.token.claim': 'true',
                        'userinfo.token.claim': 'true'}}]}
        scope_2 = ClientScope(rep=scoperep)
        self.assertFalse(
            scope.need_change(scope_2),
            "Scope changed but not supposed to")

    def test_CompareDifferentClientScopesChangedIsTrue(self):
        scope = ClientScope(rep=self.clientScopeTest)
        scope.name = "test2"
        scope.protocolMappers[0].name = "test2"
        scope_2 = ClientScope(rep=self.clientScopeTest)
        self.assertTrue(
            scope.need_change(scope_2),
            "Scope changed but not supposed to")

    def test_ProtocolMapperFromModuleParams(self):
        module_param = {}
        mapper_param = self.clientScopeTest['protocolMappers'][0]
        module_param['name'] = mapper_param.get('name')
        module_param['protocol'] = mapper_param.get('protocol')
        module_param['protocolMapper'] = mapper_param.get('protocolMapper')
        module_param['consentRequired'] = mapper_param.get('consentRequired')
        module_param['config'] = mapper_param.get('config')
        mapper = ProtocolMapper(module_params=module_param)
        self.assertEqual(
            mapper.name,
            self.clientScopeTest['protocolMappers'][0]['name'],
            "Incorrect protocol mapper name. {0} != {1}".format(
                mapper.name,
                self.clientScopeTest['protocolMappers'][0]['name']))
        self.assertEqual(
            mapper.protocol,
            self.clientScopeTest['protocolMappers'][0]['protocol'],
            "Incorrect protocol mapper protocol. {0} != {1}".format(
                mapper.protocol,
                self.clientScopeTest['protocolMappers'][0]['protocol']))
        self.assertEqual(
            mapper.protocolMapper,
            self.clientScopeTest['protocolMappers'][0]['protocolMapper'],
            "Incorrect protocol mapper protocolMapper. {0} != {1}".format(
                mapper.protocolMapper,
                self.clientScopeTest['protocolMappers'][0]['protocolMapper']))
        self.assertEqual(
            mapper.consentRequired,
            self.clientScopeTest['protocolMappers'][0]['consentRequired'],
            "Incorrect protocol mapper consentRequired. {0} != {1}".format(
                mapper.consentRequired,
                self.clientScopeTest['protocolMappers'][0]['consentRequired']))
        self.assertEqual(mapper.config,
                         self.clientScopeTest['protocolMappers'][0]['config'],
                         "Incorrect protocol mapper config. {0} != {1}".format(str(mapper.config),
                                                                               str(self.clientScopeTest['protocolMappers'][0]['config'])))
