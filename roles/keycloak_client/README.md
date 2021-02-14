Role: keycloak_client
=========

Ce rôle permet de créer un client OpenID Connect dans Keycloak

Pré-requis
------------

Ce rôle a été testé sur Centos 7.
Pour exécuter ce rôle, il est nécessaires d'avoir accès au dépôt git Ansible de l'INSPQ et de réserver la branche inspq afin de pouvoir utiliser les modules Ansible pour Keycloak.

Variables du rôle
-----------------

Voici la liste des variables:

	keycloak_url: URL du serveur Keycloak ou céer le client
	keycloak_user: Nom d'utilisateur pour se connecter dans Keycloak
	keycloak_password: Mot de passe de l'utilisateur
	oidc_realm: Domaine dans lequel créer le client.
	oidc_client_id: ClientID a assigner au nouveau client.
	oidc_client_name: Nom du client a créer
	oidc_client_description: Description du client.
	oidc_client_redirectUris: Liste des URI de redirection accepté par le client.
	oidc_client_weborigins: Liste des origines acceptés par le client.
	oidc_client_bearerOnly: booléen indiquant si le client a créer est de type bearerOnly.
	oidc_client_publicClient: booléen indiquant sir le client est publique.
	oidc_client_authorizationServicesEnabled: booléen indiquant s'il faut ou non activer les services d'autorisations pour ce client.
	oidc_client_serviceAccountsEnabled: booléen indiquant s'il faut créer un comte de service. Doit être True si oidc_client_authorizationServicesEnabled est True
	
ce rôle retourne le client secret dans la variable suivante dans le cas ou le client n'est pas publique ni bearer only:

	oidc_client_secret

Dépendances
-----------

Ce rôle dépend des rôles suivants:

	- config_base_centos

Exemple de Playbook
----------------

Voici un exemple de playbook :

    - hosts: servers
      roles:
      - role: keycloak_client
    	oidc_realm: "{{ sx5403_oidc_realm }}"
        oidc_client_id: "{{ sx5403_oidc_client_id }}"
        oidc_client_name: "{{ sx5403_oidc_client_name }}"
        oidc_client_description: "{{ sx5403_oidc_client_description }}"
        oidc_client_redirectUris : "{{ sx5403_oidc_client_redirectUris }}"
        oidc_client_weborigins: "{{ sx5403_oidc_client_weborigins }}"
        oidc_client_publicClient: true
        oidc_client_authorizationServicesEnabled: false

Licence
-------

LiLiQ-P https://forge.gouv.qc.ca/licence/liliq-v1-1/

Auteur
------------------

Institut national de santé publique du Québec.
