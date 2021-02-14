Role Name
=========

Ce rôle Ansible permet d'installer et configurer un serveur Keycloak pour la fédération d'identités.
Si roulé sur Centos ou RHEL, Apache sera installé et une configuration d'hôte virtuel avec mod_proxy sera créé pour exposer le serveur Keycloak.

Pré-requis
------------

Ce rôle utilise les modules Keycloak développés par l'INSPQ. Ces modules sont inclus dans cette collection.

Variables du rôle
--------------

Voici les variables utilisées par le rôle:

	app_user: Usager unix qui exécute Keycloak (défaut: jboss)
	app_user_id: ID de l'usager unix qui exécute Keycloak (défaut: 1000)
	app_group: Groupe unix qui exécute Keycloak (défaut: jboss)
	app_group_id: ID du groupe unix qui exécute Keycloak (défaut: 1000)
	docker_registry: Adresse du référentiel Docker (défaut: nexus3.inspq.qc.ca:5000)
	delete_existing_container: Si vraie, le conteneur keycloak sera supprimé er re-créé (défaut: false)
	keycloak_image: Image docker a utiliser pour Keycloak (défaut: {{ docker_registry }}/inspq/keycloak)
	keycloak_image_version: Version de l'image a utiliser (défaut: latest)
	keycloak_user: Identifiant de l'administrateur Keycloak a créer (défaut: admin)
	keycloak_password: Mot de passe de l'administrateur Keycloak (défaut: admin)
	keycloak_external_port: Port sur lequel exposer Keycloak (défaut: 18081)
	keycloak_base_url: Nom d'hôte utilisé pour l'URL de base qui expose le serveur (défaut: {{ ansible_hostname }}.inspq.qc.ca)
	keycloak_protocol: Protocol utilisé: http ou https (défaut: http)
	keycloak_url: URL du serveur keycloak (défaut: "{{ keycloak_protocol }}://{{ keycloak_base_url }}:{{ keycloak_external_port }}")
	keycloak_vhost_protocol: Protocol utilisé par le virtualhost Apache qui expose le serveur Keycloak. Par défaut: "{{ keycloak_protocol }}", cette valeur pourrait être http si keycloak_protocol est https etun load balancer est utilisé.
	keycloak_cert_file: Fichier de certificat à utiliser pour le SSL, obligatoire si le protocol est https
	keycloak_cert_key: Fichier de clé pour le certificat, obligatoire pour https
	keycloak_container_name: Nom du conteneur (défaut: keycloak)
	keycloak_loglevel: Niveau de verbosité des journaux (défaut: INFO, peut être DEBUG, WARNING, ERROR etc.)
	keycloak_cert_path: Répertoire dans lequel se retrouve les certificats pour le vhost Apache (défaut: certificats)
	keycloak_config: Nom du fichier de configuration à utiliser pour le serveur Keycloak (défaut: standalone.xml)
	keycloak_ha_config: Si défini, la topologie cluster sera utilisé pour le déploiement. Cette variable défini le nom du fichier de configuration HA à utiliser pour le cluster Keycloak. (ex. standalone_ha.xml)
	keycloak_docker_network_driver: Pilote réseau a utiliser pour le réseau interne lors du déploijement d'un cluster Keycloak. Les valeurs supportés sont overlay ou macvlan.
	keycloak_docker_network_name: Nom du réseau interne reliant les noeuds du cluster. Nécessaire seulement lors d'une configuration cluster. On utilise la valeur reseau_macvlan pour le mode macvlan et keycloak lors de l'utilisation du pilote overlay.
	keycloak_docker_network_subnet: Sous-réseau à utiliser pour le réseau overlay (ex. 192.168.122.0/28)
	keycloak_cluster_initial_hosts: Liste des membres du cluster lors de l'utilisation du pilote réseau overlay. (ex.{{ keycloak_container_name }}_SERVEUR1.{{ keycloak_docker_network_name }}[7600],{{ keycloak_container_name }}_SERVEUR2.{{ keycloak_docker_network_name }}[7600],{{ keycloak_container_name }}_SERVEUR2.{{ keycloak_docker_network_name }}[7600])
	keycloak_db_addr: Adresse du serveur de base de données. Pour image jboss/keycloak. Ex. postgres
	keycloak_db_port: Port du serveur de base de données. Pour image jboss/keycloak. Ex. 5432
	keycloak_db_database: Nom de la base de données. Pour image jboss/keycloak. Ex. keycloak
	keycloak_db_vendor: Fournisseur de la base de données. Pour image jboss/keycloak. Ex. postgres	
	keycloak_db_url: URL JDBC de la base de données à utiliser pour Keycloak. Si nulle, H2 sera utilisé
	keycloak_db_username: Nom d'utilisateur pour se connecter à la base de données. Nécessaire si keycloak_db_url est défini.
	keycloak_db_password: Mot de passe pour la connexion à la base de données. Nécessaire si keycloak_db_url est défini.
	keycloak_db_driver: Pilote JDBC à utiliser: postgresql, sqlserver ou oracle
	keycloak_proxy_address_forwarding: Utilisation d'un reverse proxy: True|False défaut False
	keycloak_jgroups_discovery_protocols: Protocol à utiliser pour la décourverte des membres du cluster. Défault: JDBC_PING
    keycloak_jgroups_discovery_properties: Propriétés supplémentaire pour le protocol de découverte.
	keycloak_graylog_host: Adresse du serveur graylog, si cette valeur est nulle, graylog ne sera pas utilisé.
	keycloak_graylog_gelf_tcp: Port de l'entré GELF TCP du serveur Graylog si nécessaire.
	keycloak_graylog_gelf_udp: Port de l'entré GELF UDP du serveur Graylog si nécessaire.
	keycloak_graylog_rotate_size: Grosseur des fichiers de journalisation qui déclanche la rotation des fichiers.
	keycloak_graylog_nb_file: Nombre de fichiers de journaux a conserver.
	keycloak_graylog_log_file: Nom des fichiers de journalisation.
	keycloak_log_driver: Pilote de journalisation a utiliser pour le conteneur Docker. gelf est supporté.
	keycloak_log_options: Options de configuration du pilote de journalisation. Utiliser la structure suivante pour gelf:
		keycloak_log_options:
			gelf-address: "udp://{{ keycloak_graylog_host }}:{{ keycloak_graylog_gelf_udp }}"
	keycloak_debug_port: Port pour de débug a distance. Ne pas utiliser en production (ne pas définir la variable).
	keycloak_realms: Liste de REALMs a créer.
	keycloak_authentication_flows: Liste de flot d'authentification à créer.
	keycloak_idps: Liste des fournisseurs d'identités à créer.
	keycloak_idps_clients: Liste de clients à créer dans des serveurs Keycloak servant de fournisseurs d'identités externes pour lesquels on a des autorisations suffisantes pour le faire.
	keycloak_roles: Liste de rôle à créer.
	keycloak_clients: Liste de clients OpenIDConnect à créer sur le serveur Keycloak.
	keycloak_components: Liste de composants à créer. Pour le moment, le seul composant supporté est la fédération d'un LDAP externe.
	keycloak_groups: Liste de groupes à créer.
	keycloak_users: Liste d'utilisateur à créer.

	keycloak_container_type: Type d'engin d'exécution des conteneurs: docker ou kubernetes. Défaut: docker
	
	# Variables pour Kubernetes. Ces variable ne sont utilisé que si keycloak_container_type est kubernetes
	keycloak_kube_namespace: Namespace à utiliser. Défaut keycloak
	keycloak_kube_app_name: Label app a donnéer au composants Kubernetes. Défaut kubernetes
	keycloak_kube_service_name: Nom du service. Défaut: service-{{ keycloak_kube_app_name }}
	keycloak_kube_service_port: Port à utiliser pour le service. Défaut 8080
	keycloak_kube_replicas: Nombre de réplica à créer. Défaut 1
	keycloak_kube_ingress_name: Nom du ingress. Défaut ingress-{{ keycloak_kube_app_name }}
	keycloak_kube_certificate_name: Nom du certificat à créer. Défaut "", ne créé pas de certificat
	keycloak_kube_certificate_issuer: Emetteur du certificat. Défaut ""
	keycloak_kube_certificate_org: Organisation associé au certificat. Défaut ""
	

Dependances
------------

Ce rôle dépend des rôles suivants:

	- docker-engine

Example de Playbook
----------------

Voici un exemple de playbook.  

    - hosts: servers
      roles:
         - { role: keycloak }
         
Ce playbook permet de créer un conteneur keycloak de base qui écoute sur le port 18081. Il est alort accessible à l'adresse suivante:

	http://{{ ansible_hostname }}.inspq.qc.ca:18081
	
S'il est utilisé sur un serveur Centos, un virtualhost Apache est créé et il est accessible par le port 80 à l'adresse suivante:

	http://{{ ansible_hostname }}.inspq.qc.ca
	
On peut s'authentifier en utilisant les informations suivantes:

	Identifiant: admin
	Mot de passe: admin
	
Le données sont mis dans une base de données H2 à l'intérieur du conteneur. Le données sont donc perdues lorsqu'on supprime le conteneur.

Tests Clustering
----------------
Pour tester un déploiement en cluster, suivre les étapes suivantes.
L'image utilisée doit supporter les jgroups de type JDBC_PING. Voir le projet Keycloak de l'INSPQ: https://gitlab.forge.gouv.qc.ca/inspq/docker/keycloak.git

Utiliser le fichier de configuration ansible.cfg inclus dans le projet

Installer les rôles Ansible dont ce rôle dépend dans le répertoires roles. Voir projet https://gitlab.forge.gouv.qc.ca/ansible-inspq/roles/docker-engine.git

Créer un conteneur PostgreSQL

	roles/keycloak/tests/CLUSTER/testpostgres.sh
	
Créer le premier serveur Keycloak

	ansible-playbook -i roles/keycloak/tests/CLUSTER/HOST1/HOST1.hosts -e keycloak_image=nexus3.inspq.qc.ca:5000/inspq/keycloak -e keycloak_image_version=9.0.3 roles/keycloak/tests/test.yml

Créer le deuxième neeud du cluster

	ansible-playbook -i roles/keycloak/tests/CLUSTER/HOST2/HOST2.hosts -e keycloak_image=nexus3.inspq.qc.ca:5000/inspq/keycloak -e keycloak_image_version=9.0.3 roles/keycloak/tests/test.yml	

Déploiement Kubernetes
----------------------
Pour tester un déploiement sous Kubernetes, on peut utiliser l'inventaire tests/Kubernetes
Cet inventaire permet de créer un Deployment, un service et un ingress pour Keycloak. 
L'ingress est répond par défaut à l'URL keycloak.test.com

### Pré-requis
Pour que ca fonctionne, le cluster Kubernetes doit exister.
L'utilisateur root de la machine sur lequel on exécute le playbook doit avoir un fichier de configuration /root/.kube/config 
contenant les informations de connnexion et d'authentification auprès du cluster kubernetes. 
Les informations de connexion doivent permettre d'obtenir le rôle cluster admin pour Kubernetes.
Dans notre exemple on utilise l'opérateur Crunchy Data pour créer un cluster Postgres:  https://github.com/CrunchyData/postgres-operator 
On utilise rook-ceph comme stockage: https://rook.io
Dans le cas de la création d'un certificat, c'est cert-manager qui est utilisé: https://github.com/jetstack/cert-manager

### Créer le cluster Postgres

On doit créer un cluster postgres.
Dans l'exemple suivant, on créé un cluster Crunchy à un noeud et une relève.
	Exposer l'opérateur
		kubectl port-forward -n pgo svc/postgres-operator 8443:8443 &
    Créer le namespace
    	pgo create namespace keycloak
    Créer le cluster de base de données et la base de données de Keycloak
    	pgo create cluster postgres -n keycloak --database=keycloak --username=keycloak --password=keycloak --storage-config=rook --pgbackrest-storage-config=rook
La création d'un seul serveur postgres avec stockage local peut aussi bien faire l'affaire.
    
### Exécution du playbook

Ajouter l'authentification au registre docker dans le namespace keycloak si nécessaire
	kubectl create secret generic regcred --from-file=.dockerconfigjson=${HOME}/.docker/config.json --type=kubernetes.io/dockerconfigjson -n keycloak

L'URL spécifié par la variable keycloak_base_url doit résoudre au niveau du DNS et correspondre à l'adresse externe du cluster Kubernetes	
Créer le cluster Keycloak
	ansible-playbook -i roles/keycloak/tests/KUBERNETES/KUBERNETES.hosts -e keycloak_base_url=keycloak.test.com roles/keycloak/tests/test.yml


Licence
-------

LiLiQ-P https://forge.gouv.qc.ca/licence/liliq-v1-1/

Auteur
------------------

Institut national de santé publique du Québec.