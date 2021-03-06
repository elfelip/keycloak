#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Eike Frost <ei@kefro.st>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: keycloak_client

short_description: Allows administration of Keycloak clients via Keycloak API

description:
    - This module allows the administration of Keycloak clients via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

    - The names of module options are snake_cased versions of the camelCase ones found in the
      Keycloak API and its documentation at U(http://www.keycloak.org/docs-api/3.3/rest-api/).
      Aliases are provided so camelCased versions can be used as well.

    - The Keycloak API does not always sanity check inputs e.g. you can set
      SAML-specific settings on an OpenID Connect client for instance and vice versa. Be careful.
      If you do not specify a setting, usually a sensible default is chosen.

options:
    state:
        description:
            - State of the client
            - On C(present), the client will be created (or updated if it exists already).
            - On C(absent), the client will be removed if it exists
        choices: ['present', 'absent']
        default: 'present'
        type: str
    realm:
        description:
            - The realm to create the client in.
        type: str
        default: master
    client_id:
        description:
            - Client id of client to be worked on. This is usually an alphanumeric name chosen by
              you. Either this or I(id) is required. If you specify both, I(id) takes precedence.
              This is 'clientId' in the Keycloak REST API.
        aliases:
            - clientId
        type: str
    id:
        description:
            - Id of client to be worked on. This is usually an UUID. Either this or I(client_id)
              is required. If you specify both, this takes precedence.
        type: str
    name:
        description:
            - Name of the client (this is not the same as I(client_id))
        type: str
    description:
        description:
            - Description of the client in Keycloak
        type: str
    root_url:
        description:
            - Root URL appended to relative URLs for this client
              This is 'rootUrl' in the Keycloak REST API.
        aliases:
            - rootUrl
        type: str
    admin_url:
        description:
            - URL to the admin interface of the client
              This is 'adminUrl' in the Keycloak REST API.
        aliases:
            - adminUrl
        type: str
    base_url:
        description:
            - Default URL to use when the auth server needs to redirect or link back to the client
              This is 'baseUrl' in the Keycloak REST API.
        aliases:
            - baseUrl
        type: str
    enabled:
        description:
            - Is this client enabled or not?
        type: bool
    client_authenticator_type:
        description:
            - How do clients authenticate with the auth server? Either C(client-secret) or
              C(client-jwt) can be chosen. When using C(client-secret), the module parameter
              I(secret) can set it, while for C(client-jwt), you can use the keys C(use.jwks.url),
              C(jwks.url), and C(jwt.credential.certificate) in the I(attributes) module parameter
              to configure its behavior.
              This is 'clientAuthenticatorType' in the Keycloak REST API.
        choices: ['client-secret', 'client-jwt']
        aliases:
            - clientAuthenticatorType
        type: str
    secret:
        description:
            - When using I(client_authenticator_type) C(client-secret) (the default), you can
              specify a secret here (otherwise one will be generated if it does not exit). If
              changing this secret, the module will not register a change currently (but the
              changed secret will be saved).
        type: str
    registration_access_token:
        description:
            - The registration access token provides access for clients to the client registration
              service.
              This is 'registrationAccessToken' in the Keycloak REST API.
        aliases:
            - registrationAccessToken
        type: str
    default_roles:
        description:
            - list of default roles for this client. If the client roles referenced do not exist
              yet, they will be created.
              This is 'defaultRoles' in the Keycloak REST API.
        aliases:
            - defaultRoles
        type: list
        elements: str
    redirect_uris:
        description:
            - Acceptable redirect URIs for this client.
              This is 'redirectUris' in the Keycloak REST API.
        aliases:
            - redirectUris
        type: list
        elements: str
    web_origins:
        description:
            - List of allowed CORS origins.
              This is 'webOrigins' in the Keycloak REST API.
        aliases:
            - webOrigins
        type: list
        elements: str
    not_before:
        description:
            - Revoke any tokens issued before this date for this client (this is a UNIX timestamp).
              This is 'notBefore' in the Keycloak REST API.
        aliases:
            - notBefore
        type: int
    bearer_only:
        description:
            - The access type of this client is bearer-only.
              This is 'bearerOnly' in the Keycloak REST API.
        aliases:
            - bearerOnly
        type: bool
    consent_required:
        description:
            - If enabled, users have to consent to client access.
              This is 'consentRequired' in the Keycloak REST API.
        aliases:
            - consentRequired
        type: bool
    standard_flow_enabled:
        description:
            - Enable standard flow for this client or not (OpenID connect).
              This is 'standardFlowEnabled' in the Keycloak REST API.
        aliases:
            - standardFlowEnabled
        type: bool
    implicit_flow_enabled:
        description:
            - Enable implicit flow for this client or not (OpenID connect).
              This is 'implicitFlowEnabled' in the Keycloak REST API.
        aliases:
            - implicitFlowEnabled
        type: bool
    direct_access_grants_enabled:
        description:
            - Are direct access grants enabled for this client or not (OpenID connect).
              This is 'directAccessGrantsEnabled' in the Keycloak REST API.
        aliases:
            - directAccessGrantsEnabled
        type: bool
    service_accounts_enabled:
        description:
            - Are service accounts enabled for this client or not (OpenID connect).
              This is 'serviceAccountsEnabled' in the Keycloak REST API.
        aliases:
            - serviceAccountsEnabled
        type: bool
    authorization_services_enabled:
        description:
            - Are authorization services enabled for this client or not (OpenID connect).
              This is 'authorizationServicesEnabled' in the Keycloak REST API.
        aliases:
            - authorizationServicesEnabled
        type: bool
    public_client:
        description:
            - Is the access type for this client public or not.
              This is 'publicClient' in the Keycloak REST API.
        aliases:
            - publicClient
        type: bool
    frontchannel_logout:
        description:
            - Is frontchannel logout enabled for this client or not.
              This is 'frontchannelLogout' in the Keycloak REST API.
        aliases:
            - frontchannelLogout
        type: bool
    protocol:
        description:
            - Type of client (either C(openid-connect) or C(saml).
        choices: ['openid-connect', 'saml']
        default: openid-connect
        type: str
    full_scope_allowed:
        description:
            - Is the "Full Scope Allowed" feature set for this client or not.
              This is 'fullScopeAllowed' in the Keycloak REST API.
        aliases:
            - fullScopeAllowed
        type: bool
    node_re_registration_timeout:
        description:
            - Cluster node re-registration timeout for this client.
              This is 'nodeReRegistrationTimeout' in the Keycloak REST API.
        aliases:
            - nodeReRegistrationTimeout
        type: int
    registered_nodes:
        description:
            - dict of registered cluster nodes (with C(nodename) as the key and last registration
              time as the value).
              This is 'registeredNodes' in the Keycloak REST API.
        aliases:
            - registeredNodes
        type: dict
    client_template:
        description:
            - Client template to use for this client. If it does not exist this field will silently
              be dropped.
              This is 'clientTemplate' in the Keycloak REST API.
        aliases:
            - clientTemplate
        type: str
    use_template_config:
        description:
            - Whether or not to use configuration from the I(client_template).
              This is 'useTemplateConfig' in the Keycloak REST API.
        aliases:
            - useTemplateConfig
        type: bool
    use_template_scope:
        description:
            - Whether or not to use scope configuration from the I(client_template).
              This is 'useTemplateScope' in the Keycloak REST API.
        aliases:
            - useTemplateScope
        type: bool
    use_template_mappers:
        description:
            - Whether or not to use mapper configuration from the I(client_template).
              This is 'useTemplateMappers' in the Keycloak REST API.
        aliases:
            - useTemplateMappers
        type: bool
    surrogate_auth_required:
        description:
            - Whether or not surrogate auth is required.
              This is 'surrogateAuthRequired' in the Keycloak REST API.
        aliases:
            - surrogateAuthRequired
        type: bool
    authorization_settings:
        description:
            - a data structure defining the authorization settings for this client. For reference,
              please see the Keycloak API docs at U(http://www.keycloak.org/docs-api/3.3/rest-api/index.html#_resourceserverrepresentation).
              This is 'authorizationSettings' in the Keycloak REST API.
        aliases:
            - authorizationSettings
        type: dict
    protocol_mappers:
        description:
            - a list of dicts defining protocol mappers for this client.
              This is 'protocolMappers' in the Keycloak REST API.
        aliases:
            - protocolMappers
        type: list
        elements: dict
        suboptions:
            consentRequired:
                description:
                    - Specifies whether a user needs to provide consent to a client for this mapper to be active.
                type: bool
            consentText:
                description:
                    - The human-readable name of the consent the user is presented to accept.
                type: str
            id:
                description:
                    - Usually a UUID specifying the internal ID of this protocol mapper instance.
                type: str
            name:
                description:
                    - The name of this protocol mapper.
                type: str
            protocol:
                description:
                    - This is either C(openid-connect) or C(saml), this specifies for which protocol this protocol mapper
                      is active.
                choices: ['openid-connect', 'saml']
                type: str
            protocolMapper:
                description:
                    - The Keycloak-internal name of the type of this protocol-mapper. While an exhaustive list is
                      impossible to provide since this may be extended through SPIs by the user of Keycloak,
                      by default Keycloak as of 3.4 ships with at least
                    - C(docker-v2-allow-all-mapper)
                    - C(oidc-address-mapper)
                    - C(oidc-full-name-mapper)
                    - C(oidc-group-membership-mapper)
                    - C(oidc-hardcoded-claim-mapper)
                    - C(oidc-hardcoded-role-mapper)
                    - C(oidc-role-name-mapper)
                    - C(oidc-script-based-protocol-mapper)
                    - C(oidc-sha256-pairwise-sub-mapper)
                    - C(oidc-usermodel-attribute-mapper)
                    - C(oidc-usermodel-client-role-mapper)
                    - C(oidc-usermodel-property-mapper)
                    - C(oidc-usermodel-realm-role-mapper)
                    - C(oidc-usersessionmodel-note-mapper)
                    - C(saml-group-membership-mapper)
                    - C(saml-hardcode-attribute-mapper)
                    - C(saml-hardcode-role-mapper)
                    - C(saml-role-list-mapper)
                    - C(saml-role-name-mapper)
                    - C(saml-user-attribute-mapper)
                    - C(saml-user-property-mapper)
                    - C(saml-user-session-note-mapper)
                    - An exhaustive list of available mappers on your installation can be obtained on
                      the admin console by going to Server Info -> Providers and looking under
                      'protocol-mapper'.
                type: str
            config:
                description:
                    - Dict specifying the configuration options for the protocol mapper; the
                      contents differ depending on the value of I(protocolMapper) and are not documented
                      other than by the source of the mappers and its parent class(es). An example is given
                      below. It is easiest to obtain valid config values by dumping an already-existing
                      protocol mapper configuration through check-mode in the I(existing) field.
                type: dict
            state:
                description:
                    - Desired state of the protocol mappers.
                      If present, the mapper will be added or updated.
                      If absent, the mapper will be removed
                choices: [absent, present]
                default: present
                type: str
    attributes:
        description:
            - A dict of further attributes for this client. This can contain various configuration
              settings; an example is given in the examples section. While an exhaustive list of
              permissible options is not available; possible options as of Keycloak 3.4 are listed below. The Keycloak
              API does not validate whether a given option is appropriate for the protocol used; if specified
              anyway, Keycloak will simply not use it.
        type: dict
        suboptions:
            saml.authnstatement:
                description:
                    - For SAML clients, boolean specifying whether or not a statement containing method and timestamp
                      should be included in the login response.
                type: str
            saml.client.signature:
                description:
                    - For SAML clients, boolean specifying whether a client signature is required and validated.
                type: str
            saml.encrypt:
                description:
                    - Boolean specifying whether SAML assertions should be encrypted with the client's public key.
                type: str
            saml.force.post.binding:
                description:
                    - For SAML clients, boolean specifying whether always to use POST binding for responses.
                type: str
            saml.onetimeuse.condition:
                description:
                    - For SAML clients, boolean specifying whether a OneTimeUse condition should be included in login responses.
                type: str
            saml.server.signature:
                description:
                    - Boolean specifying whether SAML documents should be signed by the realm.
                type: str
            saml.server.signature.keyinfo.ext:
                description:
                    - For SAML clients, boolean specifying whether REDIRECT signing key lookup should be optimized through inclusion
                      of the signing key id in the SAML Extensions element.
                type: str
            saml.signature.algorithm:
                description:
                    - Signature algorithm used to sign SAML documents. One of C(RSA_SHA256), C(RSA_SHA1), C(RSA_SHA512), or C(DSA_SHA1).
                type: str
            saml.signing.certificate:
                description:
                    - SAML signing key certificate, base64-encoded.
                type: str
            saml.signing.private.key:
                description:
                    - SAML signing key private key, base64-encoded.
                type: str
            saml_assertion_consumer_url_post:
                description:
                    - SAML POST Binding URL for the client's assertion consumer service (login responses).
                type: str
            saml_assertion_consumer_url_redirect:
                description:
                    - SAML Redirect Binding URL for the client's assertion consumer service (login responses).
                type: str
            saml_force_name_id_format:
                description:
                    - For SAML clients, Boolean specifying whether to ignore requested NameID subject format and using the configured one instead.
                type: str
            saml_name_id_format:
                description:
                    - For SAML clients, the NameID format to use (one of C(username), C(email), C(transient), or C(persistent))
                type: str
            saml_signature_canonicalization_method:
                description:
                    - SAML signature canonicalization method. This is one of four values, namely
                      C(http://www.w3.org/2001/10/xml-exc-c14n#) for EXCLUSIVE,
                      C(http://www.w3.org/2001/10/xml-exc-c14n#WithComments) for EXCLUSIVE_WITH_COMMENTS,
                      C(http://www.w3.org/TR/2001/REC-xml-c14n-20010315) for INCLUSIVE, and
                      C(http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments) for INCLUSIVE_WITH_COMMENTS.
                type: str
            saml_single_logout_service_url_post:
                description:
                    - SAML POST binding url for the client's single logout service.
                type: str
            saml_single_logout_service_url_redirect:
                description:
                    - SAML redirect binding url for the client's single logout service.
                type: str
            user.info.response.signature.alg:
                description:
                    - For OpenID-Connect clients, JWA algorithm for signed UserInfo-endpoint responses. One of C(RS256) or C(unsigned).
                type: str
            request.object.signature.alg:
                description:
                    - For OpenID-Connect clients, JWA algorithm which the client needs to use when sending
                      OIDC request object. One of C(any), C(none), C(RS256).
                type: str
            use.jwks.url:
                description:
                    - For OpenID-Connect clients, boolean specifying whether to use a JWKS URL to obtain client
                      public keys.
                type: str
            jwks.url:
                description:
                    - For OpenID-Connect clients, URL where client keys in JWK are stored.
                type: str
            jwt.credential.certificate:
                description:
                    - For OpenID-Connect clients, client certificate for validating JWT issued by
                      client and signed by its key, base64-encoded.
    client_roles:
        description:
            - List of roles and their composites for the client.
              Client roles can be added, updated or removed depending it's state.
        aliases:
            - clientRoles
            - roles
        type: list
        elements: dict
        suboptions:
            name:
                description:
                    - Name of the role
                type: str
            description:
                description:
                    - Description of the role
                type: str
            composite:
                description:
                    - Is the role is a composite or not.
                    - default value is False if no composites are includes, True if composites are included
                type: bool
            composites:
                description:
                    - List of composite roles
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - clientId of the client if the composite is a client role.
                        type: str
                    name:
                        description:
                            - Name of the role. It can be a realm role name or a client role name.
                        type: str
            state:
                description:
                    - Desired state for the client role
                type: str
                choices: ["present","absent"]
                default: "present"
    scope_mappings:
        description:
            - List scope mappings for the client.
              Scope mappings can be added, updated or removed depending it's state.
        aliases:
            - scopeMappings
        type: dict
        suboptions:
            realm:
                description:
                    - list of realm_access roles
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Name of realm role.
                        type: str
                    state:
                        description:
                            - Desired state of realm_access roles mappings.
                              If present, the role will be added or updated.
                              If absent, the role will be removed
                        choices: [absent, present]
                        default: present
                        type: str
            clients:
                description:
                    - list of resource_access roles
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - clientId of the client.
                        type: str
                    roles:
                        description:
                            - list of realm_access roles
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Name of realm role.
                                type: str
                            state:
                                description:
                                    - Desired state of client_access roles mappings.
                                      If present, the role will be added or updated.
                                      If absent, the role will be removed
                                choices: [absent, present]
                                default: present
                                type: str
    force:
        type: bool
        description:
            - If true, existing client will be deleted an re-created.
        default: False
extends_documentation_fragment:
    - elfelip.keycloak.keycloak
author:
    - Eike Frost (@eikef)
    - Philippe Gauthier (@elfelip)
    - Etienne Sadio (@moi8407)
'''

EXAMPLES = '''
- name: Create or update Keycloak client (minimal example)
  local_action:
    module: keycloak_client
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    client_id: test
    state: present
- name: Delete a Keycloak client
  local_action:
    module: keycloak_client
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    client_id: test
    state: absent
- name: Create or update a Keycloak client (with all the bells and whistles)
  local_action:
    module: keycloak_client
    auth_client_id: admin-cli
    auth_keycloak_url: https://auth.example.com/auth
    auth_realm: master
    auth_username: USERNAME
    auth_password: PASSWORD
    state: present
    realm: master
    client_id: test
    id: d8b127a3-31f6-44c8-a7e4-4ab9a3e78d95
    name: this_is_a_test
    description: Description of this wonderful client
    root_url: https://www.example.com/
    admin_url: https://www.example.com/admin_url
    base_url: basepath
    enabled: True
    client_authenticator_type: client-secret
    secret: REALLYWELLKEPTSECRET
    redirect_uris:
      - https://www.example.com/*
      - http://localhost:8888/
    web_origins:
      - https://www.example.com/*
    not_before: 1507825725
    bearer_only: False
    consent_required: False
    standard_flow_enabled: True
    implicit_flow_enabled: False
    direct_access_grants_enabled: False
    service_accounts_enabled: False
    authorization_services_enabled: False
    public_client: False
    frontchannel_logout: False
    protocol: openid-connect
    full_scope_allowed: false
    node_re_registration_timeout: -1
    client_template: test
    use_template_config: False
    use_template_scope: false
    use_template_mappers: no
    registered_nodes:
      node01.example.com: 1507828202
    registration_access_token: eyJWT_TOKEN
    surrogate_auth_required: false
    default_roles:
      - test01
      - test02
    protocol_mappers:
      - config:
          access.token.claim: True
          claim.name: "family_name"
          id.token.claim: True
          jsonType.label: String
          user.attribute: lastName
          userinfo.token.claim: True
        consentRequired: True
        consentText: "${familyName}"
        name: family name
        protocol: openid-connect
        protocolMapper: oidc-usermodel-property-mapper
      - config:
          attribute.name: Role
          attribute.nameformat: Basic
          single: false
        consentRequired: false
        name: role list
        protocol: saml
        protocolMapper: saml-role-list-mapper
      - config:
          multivalued: False
          userinfo.token.claim": True
          user.attribute: Test2
          id.token.claim: True
          access.token.claim: True
          claim.name: test2
          jsonType.label: String
        name: thismappermustbedeleted
        protocol: openid-connect
        protocolMapper: oidc-usermodel-attribute-mapper
        consentRequired: False
        state: absent
    attributes:
      saml.authnstatement: True
      saml.client.signature: True
      saml.force.post.binding: True
      saml.server.signature: True
      saml.signature.algorithm: RSA_SHA256
      saml.signing.certificate: CERTIFICATEHERE
      saml.signing.private.key: PRIVATEKEYHERE
      saml_force_name_id_format: False
      saml_name_id_format: username
      saml_signature_canonicalization_method: "http://www.w3.org/2001/10/xml-exc-c14n#"
      user.info.response.signature.alg: RS256
      request.object.signature.alg: RS256
      use.jwks.url: true
      jwks.url: JWKS_URL_FOR_CLIENT_AUTH_JWT
      jwt.credential.certificate: JWT_CREDENTIAL_CERTIFICATE_FOR_CLIENT_AUTH
    client_roles:
      - name: role1
        description: This is the first role
        composite: False
      - name: role2
        description: This is the second role.
        composite: True
        composites:
          - name: realmRole1
          - id: clientId1
            name: clientRole1
      - name: roleToBeDeleted
        description: This role need to be deleted
        state: absent
    scope_mappings:
      realm:
        - name: realmRole1
          state: present
        - name: realmRole2
          state: absent
      clients:
        - id: clientId1
          roles:
            - name: clientRole11
            - name: clientRole12
        - id: clientId2
          roles:
            - name: clientRole21
              state: absent
            - name: clientRole22
'''

RETURN = '''
msg:
  description: Message as to what action was taken
  returned: always
  type: str
  sample: "Client testclient has been updated"
proposed:
    description: client representation of proposed changes to client
    returned: always
    type: dict
    sample: {
      clientId: "test"
    }
existing:
    description: client representation of existing client (sample is truncated)
    returned: always
    type: dict
    sample: {
        "adminUrl": "http://www.example.com/admin_url",
        "attributes": {
            "request.object.signature.alg": "RS256",
        }
    }
clientSecret:
    description: client Secret
    returned: always
    type: dict
    sample: {
        type: "secret",
        value: "691ccfeb-13f0-4bbf-91bb-a57b42f47e31"
    }
end_state:
    description: client representation of client after module execution (sample is truncated)
    returned: always
    type: dict
    sample: {
        "adminUrl": "http://www.example.com/admin_url",
        "attributes": {
            "request.object.signature.alg": "RS256",
        }
    }
'''

from ansible_collections.elfelip.keycloak.plugins.module_utils.keycloak import KeycloakAPI, camel, \
    keycloak_argument_spec, get_token, KeycloakError
from ansible.module_utils.basic import AnsibleModule


def sanitize_cr(clientrep):
    """ Removes probably sensitive details from a client representation

    :param clientrep: the clientrep dict to be sanitized
    :return: sanitized clientrep dict
    """
    result = clientrep.copy()
    if 'secret' in result:
        result['secret'] = 'no_log'
    if 'attributes' in result:
        if 'saml.signing.private.key' in result['attributes']:
            result['attributes']['saml.signing.private.key'] = 'no_log'
    return result


def main():
    """
    Module execution

    :return:
    """
    argument_spec = keycloak_argument_spec()

    protmapper_spec = dict(
        consentRequired=dict(type='bool'),
        consentText=dict(type='str'),
        id=dict(type='str'),
        name=dict(type='str'),
        protocol=dict(type='str', choices=['openid-connect', 'saml']),
        protocolMapper=dict(type='str'),
        config=dict(type='dict'),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
    )
    clientrolecomposites_spec = dict(
        name=dict(type='str'),
        id=dict(type='str'),
    )
    clientroles_spec = dict(
        name=dict(type='str'),
        description=dict(type='str'),
        composite=dict(type='bool'),
        composites=dict(type='list', elements='dict', options=clientrolecomposites_spec),
        state=dict(type='str', choices=['absent', 'present'], default='present'),
    )
    realmscopemappings_spec = dict(
        name=dict(type='str'),
        state=dict(type='str', choices=['absent', 'present'], default='present')
    )
    clientrolescopemappings_spec = dict(
        name=dict(type='str'),
        state=dict(type='str', choices=['absent', 'present'], default='present')
    )
    clientsscopemappings_spec = dict(
        id=dict(type='str'),
        roles=dict(type='list', elements='dict', options=clientrolescopemappings_spec)
    )
    scopemappings_spec = dict(
        realm=dict(type='list', elements='dict', options=realmscopemappings_spec),
        clients=dict(type='list', elements='dict', options=clientsscopemappings_spec)
    )
    meta_args = dict(
        state=dict(default='present', choices=['present', 'absent']),
        realm=dict(type='str', default='master'),
        id=dict(type='str'),
        client_id=dict(type='str', aliases=['clientId']),
        name=dict(type='str'),
        description=dict(type='str'),
        root_url=dict(type='str', aliases=['rootUrl']),
        admin_url=dict(type='str', aliases=['adminUrl']),
        base_url=dict(type='str', aliases=['baseUrl']),
        surrogate_auth_required=dict(type='bool', aliases=['surrogateAuthRequired']),
        enabled=dict(type='bool'),
        client_authenticator_type=dict(type='str', choices=['client-secret', 'client-jwt'], aliases=['clientAuthenticatorType']),
        secret=dict(type='str', no_log=True),
        registration_access_token=dict(type='str', aliases=['registrationAccessToken']),
        default_roles=dict(type='list', elements='str', aliases=['defaultRoles']),
        redirect_uris=dict(type='list', elements='str', aliases=['redirectUris']),
        web_origins=dict(type='list', elements='str', aliases=['webOrigins']),
        not_before=dict(type='int', aliases=['notBefore']),
        bearer_only=dict(type='bool', aliases=['bearerOnly']),
        consent_required=dict(type='bool', aliases=['consentRequired']),
        standard_flow_enabled=dict(type='bool', aliases=['standardFlowEnabled']),
        implicit_flow_enabled=dict(type='bool', aliases=['implicitFlowEnabled']),
        direct_access_grants_enabled=dict(type='bool', aliases=['directAccessGrantsEnabled']),
        service_accounts_enabled=dict(type='bool', aliases=['serviceAccountsEnabled']),
        authorization_services_enabled=dict(type='bool', aliases=['authorizationServicesEnabled']),
        public_client=dict(type='bool', aliases=['publicClient']),
        frontchannel_logout=dict(type='bool', aliases=['frontchannelLogout']),
        protocol=dict(type='str', choices=['openid-connect', 'saml'], default='openid-connect'),
        attributes=dict(type='dict'),
        full_scope_allowed=dict(type='bool', aliases=['fullScopeAllowed']),
        node_re_registration_timeout=dict(type='int', aliases=['nodeReRegistrationTimeout']),
        registered_nodes=dict(type='dict', aliases=['registeredNodes']),
        client_template=dict(type='str', aliases=['clientTemplate']),
        use_template_config=dict(type='bool', aliases=['useTemplateConfig']),
        use_template_scope=dict(type='bool', aliases=['useTemplateScope']),
        use_template_mappers=dict(type='bool', aliases=['useTemplateMappers']),
        protocol_mappers=dict(type='list', elements='dict', options=protmapper_spec, aliases=['protocolMappers']),
        authorization_settings=dict(type='dict', aliases=['authorizationSettings']),
        client_roles=dict(type='list', elements='dict', options=clientroles_spec, aliases=['clientRoles', 'roles']),
        scope_mappings=dict(type='dict', aliases=['scopeMappings'], options=scopemappings_spec),
        force=dict(type='bool', default=False),
    )
    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['client_id', 'id']]))

    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={}, clientSecret='')
    connection_header = {}
    # Obtain access token, initialize API
    try:
        connection_header = get_token(
            base_url=module.params.get('auth_keycloak_url'),
            validate_certs=module.params.get('validate_certs'),
            auth_realm=module.params.get('auth_realm'),
            client_id=module.params.get('auth_client_id'),
            auth_username=module.params.get('auth_username'),
            auth_password=module.params.get('auth_password'),
            client_secret=module.params.get('auth_client_secret'),
        )
    except KeycloakError as e:
        module.fail_json(msg=str(e))

    kc = KeycloakAPI(module, connection_header)

    realm = module.params.get('realm')
    cid = module.params.get('id')
    state = module.params.get('state')

    # convert module parameters to client representation parameters (if they belong in there)
    client_params = [x for x in module.params
                     if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm', 'url', 'force'] and
                     module.params.get(x) is not None]
    keycloak_argument_spec().keys()
    # See whether the client already exists in Keycloak
    if cid is None:
        before_client = kc.get_client_by_clientid(module.params.get('client_id'), realm=realm)
        if before_client is not None:
            cid = before_client['id']
    else:
        before_client = kc.get_client_by_id(cid, realm=realm)

    if before_client is None:
        before_client = dict()

    # Build a proposed changeset from parameters given to this module
    changeset = dict()

    for client_param in client_params:
        new_param_value = module.params.get(client_param)

        # some lists in the Keycloak API are sorted, some are not.
        if isinstance(new_param_value, list):
            if client_param in ['attributes']:
                try:
                    new_param_value = sorted(new_param_value)
                except TypeError:
                    pass
        # Unfortunately, the ansible argument spec checker introduces variables with null values when
        # they are not specified
        if client_param == 'protocol_mappers':
            new_param_value = [dict((k, v) for k, v in x.items() if x[k] is not None) for x in new_param_value]

        if client_param == 'roles':
            client_param = 'client_roles'
        changeset[camel(client_param)] = new_param_value

    newClientScopeMappings = {}
    newClientScopeRealm = {}
    newClientScopeClients = {}
    if module.params.get('scope_mappings') is not None:
        newClientScopeMappings["scope_mappings"] = module.params.get('scope_mappings')
        if newClientScopeMappings["scope_mappings"]["realm"] is not None:
            newClientScopeRealm["realmRoles"] = newClientScopeMappings["scope_mappings"]["realm"]
        if newClientScopeMappings["scope_mappings"]["clients"] is not None:
            newClientScopeClients["clientRoles"] = newClientScopeMappings["scope_mappings"]["clients"]

    # Whether creating or updating a client, take the before-state and merge the changeset into it
    updated_client = before_client.copy()
    updated_client.update(changeset)

    result['proposed'] = sanitize_cr(changeset)
    result['existing'] = sanitize_cr(before_client)

    # If the client does not exist yet, before_client is still empty
    if before_client == dict():
        if state == 'absent':
            # do nothing and exit
            if module._diff:
                result['diff'] = dict(before='', after='')
            result['msg'] = 'Client does not exist, doing nothing.'
            module.exit_json(**result)

        # create new client
        result['changed'] = True
        if 'clientId' not in updated_client:
            module.fail_json(msg='client_id needs to be specified when creating a new client')

        if module._diff:
            result['diff'] = dict(before='', after=sanitize_cr(updated_client))

        if module.check_mode:
            module.exit_json(**result)

        kc.create_client(updated_client, realm=realm)
        after_client = kc.get_client_by_clientid(updated_client['clientId'], realm=realm)

        result['end_state'] = sanitize_cr(after_client)
        client_secret = kc.get_client_secret_by_id(after_client['id'], realm=realm)
        if client_secret is not None:
            result['clientSecret'] = client_secret

        if module.params.get('scope_mappings') is not None:
            kc.assing_scope_roles_to_client(
                client_id=after_client['id'],
                clientScopeRealmRoles=newClientScopeRealm["realmRoles"],
                clientScopeClientRoles=newClientScopeClients["clientRoles"],
                realm=realm)
            result['changed'] = True
        result['msg'] = 'Client %s has been created.' % updated_client['clientId']
        module.exit_json(**result)
    else:
        if state == 'present':
            # update existing client
            result['changed'] = True
            if module.check_mode:
                # We can only compare the current client with the proposed updates we have
                if module._diff:
                    result['diff'] = dict(before=sanitize_cr(before_client),
                                          after=sanitize_cr(updated_client))
                result['changed'] = (before_client != updated_client)

                module.exit_json(**result)

            kc.update_client(cid, updated_client, realm=realm)

            after_client = kc.get_client_by_id(cid, realm=realm)
            client_secret = kc.get_client_secret_by_id(cid, realm=realm)

            if client_secret is not None:
                result['clientSecret'] = client_secret
            if before_client == after_client:
                result['changed'] = False
            if module._diff:
                result['diff'] = dict(before=sanitize_cr(before_client),
                                      after=sanitize_cr(after_client))

            if module.params.get('scope_mappings') is not None:
                result['changed'] = kc.assing_scope_roles_to_client(
                    client_id=after_client['id'],
                    clientScopeRealmRoles=newClientScopeRealm["realmRoles"],
                    clientScopeClientRoles=newClientScopeClients["clientRoles"],
                    realm=realm)

            result['end_state'] = sanitize_cr(after_client)

            result['msg'] = 'Client %s has been updated.' % updated_client['clientId']
            module.exit_json(**result)
        else:
            # Delete existing client
            result['changed'] = True
            if module._diff:
                result['diff']['before'] = sanitize_cr(before_client)
                result['diff']['after'] = ''

            if module.check_mode:
                module.exit_json(**result)

            kc.delete_client(cid, realm=realm)
            result['proposed'] = dict()
            result['end_state'] = dict()
            result['msg'] = 'Client %s has been deleted.' % before_client['clientId']
            module.exit_json(**result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
