from plugins.module_utils.keycloak import ClientScope, isDictEquals, get_token
from plugins.modules import keycloak_client_scope
from tests.unit.module_utils.utils import AnsibleExitJson, AnsibleFailJson, ModuleTestCase, set_module_args
import requests
import json


class KeycloakClientScopeTestCase(ModuleTestCase):
    testClientScope = {
        "name": "newclientscope",
        "description": "New Client Scope",
        "protocol": "openid-connect",
        "attributes": {
            "include.in.token.scope": "true",
            "display.on.consent.screen": "true"
        },
        "protocolMappers": [
            {
                "name": "new-mapper-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.client.audience": "admin-cli",
                    "id.token.claim": "true",
                    "access.token.claim": "true"
                }
            }
        ]
    }

    testClientScopes = [
        {
            "name": "existingclientscope",
            "description": "Already existing Client Scope",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "true"
            },
            "protocolMappers": [
                {
                    "name": "new-mapper-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": {
                        "included.client.audience": "admin-cli",
                        "id.token.claim": "true",
                        "access.token.claim": "true"
                    }
                }
            ]
        }
    ]
    kcparams = {
        "auth_keycloak_url": "http://localhost:18081/auth",
        "auth_username": "admin",
        "auth_password": "admin",
        "realm": "master"
    }
    meta_params = {
        "state": "present",
        "force": False
    }
    excudes = [
        "auth_keycloak_url",
        "auth_username",
        "auth_password",
        "state",
        "force",
        "realm",
        "composites",
        "_ansible_keep_remote_files",
        "_ansible_remote_tmp"]
    kc = None
    baseurl = "http://localhost:18081"

    def setUp(self):
        super(KeycloakClientScopeTestCase, self).setUp()
        self.module = keycloak_client_scope
        username = "admin"
        password = "admin"
        self.clientScopesUrl = "{baseurl}/auth/admin/realms/master/client-scopes"
        self.clientScopeUrl = self.clientScopesUrl + "/{id}"
        self.clientScopeProtocolMappersBaseUrl = self.clientScopeUrl + "/protocol-mappers"
        self.clientScopeProtocolMapperAddModelsBaseUrl = self.clientScopeProtocolMappersBaseUrl + "/add-models"
        # Create Client scope
        self.headers = get_token(
            base_url=self.baseurl + '/auth',
            auth_realm="master",
            client_id="admin-cli",
            auth_username=username,
            auth_password=password,
            validate_certs=False,
            client_secret=None)

        for testClientScope in self.testClientScopes:
            getResponse = requests.get(
                self.clientScopesUrl.format(baseurl=self.baseurl),
                headers=self.headers)
            scopes = getResponse.json()
            scopeFound = False
            for scope in scopes:
                if scope['name'] == testClientScope['name']:
                    scopeFound = True
                    break
            if not scopeFound:
                data = json.dumps(testClientScope)
                postResponse = requests.post(
                    self.clientScopesUrl.format(baseurl=self.baseurl),
                    headers=self.headers,
                    data=data)
                print("Status code: {0}".format(str(postResponse.status_code)))

    def tearDown(self):
        allClientScopes = self.testClientScopes.copy()
        allClientScopes.append(self.testClientScope.copy())
        for testClientScope in allClientScopes:
            getResponse = requests.get(
                self.clientScopesUrl.format(baseurl=self.baseurl),
                headers=self.headers)
            scopes = getResponse.json()
            scopeFound = False
            scope = {}
            for scope in scopes:
                if 'name' in scope and 'name' in testClientScope and scope[
                        'name'] == testClientScope['name']:
                    scopeFound = True
                    break
            if scopeFound:
                id = scope['id']
                deleteResponse = requests.delete(
                    self.clientScopeUrl.format(baseurl=self.baseurl, id=id),
                    headers=self.headers)
                print("Status code: {0}".format(
                    str(deleteResponse.status_code)))

    def test_create_new_client_scope(self):
        toCreate = self.testClientScope.copy()
        toCreate.update(self.kcparams.copy())
        toCreate.update(self.meta_params.copy())
        toCreate["state"] = "present"
        set_module_args(toCreate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        self.assertTrue(results.exception.args[0]['changed'])
        scope = ClientScope(rep=self.testClientScope)
        created_scope = ClientScope(
            rep=results.exception.args[0]['client_scope'])
        self.assertFalse(
            scope.need_change(created_scope),
            "asked: {}, created: {}".format(
                str(scope.getRepresentation()),
                str(created_scope.getRepresentation())))

    def test_update_client_scope_description(self):
        toUpdate = self.testClientScopes[0].copy()
        toUpdate.update(self.kcparams.copy())
        toUpdate.update(self.meta_params.copy())
        toUpdate["state"] = "present"
        toUpdate['description'] = 'Changed description'
        set_module_args(toUpdate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        self.assertTrue(results.exception.args[0]['changed'])
        scope = ClientScope(rep=self.testClientScopes[0])
        updated_scope = ClientScope(
            rep=results.exception.args[0]['client_scope'])
        self.assertEquals(
            updated_scope.description,
            toUpdate['description'],
            'Scope has not been updated: asked: {}, updated {}'.format(
                updated_scope.description,
                toUpdate['description']
            )
        )

        self.assertTrue(
            scope.need_change(updated_scope),
            "Client scope has not change. asked: {}, created: {}".format(
                str(scope.getRepresentation()),
                str(updated_scope.getRepresentation())))

    def test_update_client_scope_without_change(self):
        toUpdate = self.testClientScopes[0].copy()
        toUpdate.update(self.kcparams.copy())
        toUpdate.update(self.meta_params.copy())
        toUpdate["state"] = "present"
        set_module_args(toUpdate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        self.assertFalse(results.exception.args[0]['changed'])

    def test_update_client_scope_protocol_mapper_included_client_audience(
            self):
        toUpdate = self.testClientScopes[0].copy()
        toUpdate.update(self.kcparams.copy())
        toUpdate.update(self.meta_params.copy())
        toUpdate["state"] = "present"
        toUpdate['protocolMappers'][0]['config']['included.client.audience'] = 'account'
        set_module_args(toUpdate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        self.assertTrue(results.exception.args[0]['changed'])
        scope = ClientScope(rep=self.testClientScopes[0])
        updated_scope = ClientScope(
            rep=results.exception.args[0]['client_scope'])
        self.assertEquals(
            updated_scope.protocolMappers[0].config['included.client.audience'],
            'account',
            'Included client audience prodocol mapper config has not been updated: {}'.format(
                updated_scope.protocolMappers[0].config['included.client.audience']))
        self.assertFalse(
            scope.need_change(updated_scope),
            "Client scope has not change. asked: {}, created: {}".format(
                str(scope.getRepresentation()),
                str(updated_scope.getRepresentation())))

    def test_update_client_scope_protocol_mapper_id_token_claim(self):
        toUpdate = self.testClientScopes[0].copy()
        toUpdate.update(self.kcparams.copy())
        toUpdate.update(self.meta_params.copy())
        toUpdate["state"] = "present"
        toUpdate['protocolMappers'][0]['config']['id.token.claim'] = 'false'
        set_module_args(toUpdate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        self.assertTrue(results.exception.args[0]['changed'])
        scope = ClientScope(rep=self.testClientScopes[0])
        updated_scope = ClientScope(
            rep=results.exception.args[0]['client_scope'])
        self.assertEquals(
            updated_scope.protocolMappers[0].config['id.token.claim'],
            'false',
            'Id token claim prodocol mapper config has not been updated: {}'.format(
                updated_scope.protocolMappers[0].config['id.token.claim']))
        self.assertFalse(
            scope.need_change(updated_scope),
            "Client scope has not change. asked: {}, created: {}".format(
                str(scope.getRepresentation()),
                str(updated_scope.getRepresentation())))

    def test_update_client_scope_add_protocol_mapper(self):
        toUpdate = self.testClientScopes[0].copy()
        toUpdate.update(self.kcparams.copy())
        toUpdate.update(self.meta_params.copy())
        toUpdate["state"] = "present"
        newMapper = self.testClientScopes[0]['protocolMappers'][0].copy()
        newMapper['name'] = 'added-mapper-audience'
        newMapper['config']['included.client.audience'] = 'account'
        newMapper['config']['id.token.claim'] = 'false'
        toUpdate['protocolMappers'].append(newMapper)
        set_module_args(toUpdate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        scope = ClientScope(rep=toUpdate)
        updated_scope = ClientScope(
            rep=results.exception.args[0]['client_scope'])
        self.assertTrue(results.exception.args[0]['changed'])
        self.assertEquals(
            len(updated_scope.protocolMappers),
            2,
            'Protocol Mapper not added to client scope: {}'.format(str(len(updated_scope.protocolMappers))))

    def test_update_client_scope_delete_protocol_mapper_remove(self):
        toUpdate = self.testClientScopes[0].copy()
        toUpdate.update(self.kcparams.copy())
        toUpdate.update(self.meta_params.copy())
        toUpdate["state"] = "present"
        del(toUpdate['protocolMappers'][0])
        set_module_args(toUpdate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        scope = ClientScope(rep=toUpdate)
        updated_scope = ClientScope(
            rep=results.exception.args[0]['client_scope'])
        self.assertTrue(results.exception.args[0]['changed'])
        self.assertEquals(
            len(updated_scope.protocolMappers),
            0,
            'Protocol Mapper not deleted from client scope: {}'.format(str(len(updated_scope.protocolMappers))))

    def test_update_client_scope_delete_protocol_mapper_using_state_absent(
            self):
        toUpdate = self.testClientScopes[0].copy()
        toUpdate.update(self.kcparams.copy())
        toUpdate.update(self.meta_params.copy())
        toUpdate["state"] = "present"
        toUpdate['protocolMappers'][0]['state'] = 'absent'
        set_module_args(toUpdate)
        with self.assertRaises(AnsibleExitJson) as results:
            self.module.main()
        scope = ClientScope(rep=toUpdate)
        updated_scope = ClientScope(
            rep=results.exception.args[0]['client_scope'])
        self.assertTrue(results.exception.args[0]['changed'])
        self.assertEquals(
            len(updated_scope.protocolMappers),
            0,
            'Protocol Mapper not deleted from client scope: {}'.format(str(len(updated_scope.protocolMappers))))
