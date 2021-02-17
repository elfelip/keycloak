#!/bin/bash
docker run -d \
	--rm \
	--name postgrestestkc \
	-p 15432:5432 \
	-e POSTGRES_USER=keycloak \
	-e POSTGRES_PASSWORD=Keycl0ak \
	-e POSTGRES_DB=keycloak \
	postgres:latest
