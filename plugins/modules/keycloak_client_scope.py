#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, INSPQ <philippe.gauthier@inspq.qc.ca>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: keycloak_client_scope
short_description: Configure a client scope in Keycloak
description:
    - This module creates, removes or update Keycloak client scope role.
version_added: "2.10"
options:
    realm:
        description:
            - The name of the realm in which is the client scope.
        default: master
        type: str
    name:
        description:
            - Name for the client scope.
        required: true
        type: str
    description:
        description:
            - Description of the client scope.
        required: false
        type: str
    protocol:
        description:
            - Protocol for the client scope.
        default: openid-connect
        choices:
            - openid-connect
            - saml
        type: string
    attributes:
        description:
            - Attributes for the client scope
        default: {}
        type: dict
    protocolMappers:
        description:
            - List or protocole mappers for the client scope
        required: false
        type: list
        extends_documentation_fragment:
            - keycloak_protocol_mapper

    state:
        description:
            - Control if the client scope must exists or not
        choices: [ "present", "absent" ]
        default: present
        type: str
    force:
        type: bool
        default: false
        description:
            - If true, allows to remove client role and recreate it.
extends_documentation_fragment:
    - keycloak
notes:
    - module does not modify role name.
author:
    - Philippe Gauthier (@elfelip)
'''

EXAMPLES = '''
    - name: Create a client scope.
      keycloak_client_scope:
        auth_keycloak_url: http://localhost:8080/auth
        auth_sername: admin
        auth_password: password
        auth_realm: master
        realm: master
        name: testclientscope
        description: Client scope
        protocol: openid-connect
        attributes:
            include.in.token.scope: true
            display.on.consent.screen: true
        protocolMappers: 
        - name: test-audience
          protocol: openid-connect
          protocolMapper: oidc-audience-mapper
          consentRequired: false
          config: 
            included.client.audience: admin-cli
            id.token.claim: true
            access.token.claim: true
        state: present

    - name: Remove client scope.
      keycloak_client_scope:
        auth_keycloak_url: http://localhost:8080/auth
        auth_sername: admin
        auth_password: password
        auth_realm: master
        realm: master
        name: testclientscope
        state: absent
'''

RETURN = '''
client_scope:
  description: JSON representation for the client_scope.
  returned: on success
  type: dict
protocol_mappers:
  description: Protocol mappers JSON representation for the client scope.
  returned: on success
  type: list
msg:
  description: Error message if it is the case
  returned: on error
  type: str
changed:
  description: Return True if the operation changed the client scope on the keycloak server, false otherwise.
  returned: always
  type: bool
'''
from plugins.module_utils.keycloak import KeycloakAPI, camel, \
    keycloak_argument_spec, get_token, KeycloakError, isDictEquals, ClientScope, ProtocolMapper
from ansible.module_utils.basic import AnsibleModule


def main():
    client_scope = ClientScope()
    argument_spec = keycloak_argument_spec()
    argument_spec.update(client_scope.argument_spec())
    meta_args = dict(
        realm=dict(type="str", default="master"),
        force=dict(type='bool', default=False),
    )
    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    result = dict(changed=False, msg='', client_scope={}, protocol_mappers=[])
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

    realm = module.params.get('realm')
    kc = KeycloakAPI(module, connection_header)

    client_scope = ClientScope(module_params=module.params)
    changed = False
    found_client_scopes = kc.search_client_scope_by_name(client_scope.name, realm=realm)
    if len(found_client_scopes) == 0:  # Scope does not already exists
        response = kc.create_client_scope(client_scope=client_scope, realm=realm)
        if response.code == 201:
            result['client_scope'] = kc.search_client_scope_by_name(name=client_scope.name)[0].getRepresentation()
            changed = True
    else:
        if client_scope.need_change(client_scope=found_client_scopes[0]):
            response = kc.update_client_scope(client_scope=client_scope, realm=realm)
            if response is not None and response.code == 204:
                changed = True

        result['client_scope'] = kc.get_client_scope_by_id(id=found_client_scopes[0].id).getRepresentation()

    result['changed'] = changed
    module.exit_json(**result)
    """
    # Search the role on Keycloak server.
    roleRepresentation = kc.search_realm_role_by_name(name=newRoleRepresentation["name"], realm=realm)
    if roleRepresentation == {}:  # If role does not exists
        if (state == 'present'):  # If desired state is present
            # Create Role
            kc.create_realm_role(newRoleRepresentation=newRoleRepresentation, realm=realm)
            # Create composites
            kc.create_or_update_realm_role_composites(newComposites=newComposites, newRoleRepresentation=newRoleRepresentation, realm=realm)
            # Get created role
            roleRepresentation = kc.get_realm_role(name=newRoleRepresentation["name"], realm=realm)
            # Get created composites
            composites = kc.get_realm_role_composites_with_client_id(name=newRoleRepresentation["name"], realm=realm)
            changed = True
            result['role'] = roleRepresentation
            result['composites'] = composites
        elif state == 'absent':  # If desired state is absent
            result["msg"] = "Realm role %s is absent in realm %s" % (newRoleRepresentation["name"], realm)

    else:  # If role already exists
        if (state == 'present'):  # If desired state is present
            if force:  # If force option is true
                # Delete the existing role
                kc.delete_realm_role(name=roleRepresentation["name"], realm=realm)
                # Create role again
                kc.create_realm_role(newRoleRepresentation=newRoleRepresentation, realm=realm)
                changed = True
            else:  # If force option is false
                # Compare roles
                if not (isDictEquals(newRoleRepresentation, roleRepresentation)):  # If new role introduce changes
                    # Update the role
                    kc.update_realm_role(newRoleRepresentation=newRoleRepresentation, realm=realm)
                    changed = True
            # Manage composites
            if kc.create_or_update_realm_role_composites(newComposites=newComposites, newRoleRepresentation=newRoleRepresentation, realm=realm):
                changed = True
            # Get created role
            roleRepresentation = kc.get_realm_role(name=newRoleRepresentation["name"], realm=realm)
            # Get composites
            composites = kc.get_realm_role_composites_with_client_id(name=newRoleRepresentation["name"], realm=realm)
            result["role"] = roleRepresentation
            result["composites"] = composites
        elif state == 'absent':  # If desired state is absent
            # Delete role
            kc.delete_realm_role(name=newRoleRepresentation["name"], realm=realm)
            changed = True
            result["msg"] = "Realm role %s is deleted in realm %s" % (newRoleRepresentation["name"], realm)
    result['changed'] = changed
    module.exit_json(**result)
"""

if __name__ == '__main__':
    main()
