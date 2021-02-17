#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Eike Frost <ei@kefro.st>
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    # Standard documentation fragment
    DOCUMENTATION = r'''
options:
    name:
        description:
            - Name of the protocol mapper
        type: str
        required: true
    protocol:
        description:
            - Protocol fot the mapper
        type: str
        choices:
            - openid-connect
        default: openid-connect
    protocolMapper:
        description:
            - Protocol mapper type.
        type: str
        choices:
            - oidc-audience-mapper
            - oidc-usermodel-realm-role-mapper
            - oidc-hardcoded-claim-mapper
            - oidc-sha256-pairwise-sub-mapper
            - oidc-claims-param-token-mapper
            - oidc-usersessionmodel-note-mapper
            - oidc-address-mapper
            - oidc-hardcoded-role-mapper
            - oidc-usermodel-client-role-mapper
            - oidc-usermodel-property-mapper
            - oidc-full-name-mapper
            - oidc-usermodel-attribute-mapper
            - oidc-allowed-origins-mapper
            - oidc-group-membership-mapper
            - oidc-role-name-mapper
            - oidc-audience-resolve-mapper
            - saml-javascript-mapper
            - saml-user-attribute-mapper
            - saml-hardcode-role-mapper
            - saml-hardcode-attribute-mapper
            - saml-role-name-mapper
            - saml-audience-resolve-mapper
            - saml-user-session-note-mapper
            - saml-user-property-mapper
            - saml-group-membership-mapper
            - saml-role-list-mapper
            - saml-audience-mapper
        required: true
    consentRequired:
        description:
            - Is user consent is required to apply the mapper
        type: bool
        default: false
    config:
        description:
            - Configuration parameter for the mapper.
        type: dict
        required: false
    state:
        description:
            - Control if the client scope must exists or not
        choices: [ "present", "absent" ]
        default: present
        type: str
'''
