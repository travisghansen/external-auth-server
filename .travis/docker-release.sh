#!/bin/bash

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

if [[ -n "${TRAVIS_TAG}" ]];then
	docker build --pull -t travisghansen/external-auth-server:${TRAVIS_TAG} .
	docker push travisghansen/external-auth-server:${TRAVIS_TAG}
elif [[ "${TRAVIS_BRANCH}" == "master" ]];then
	docker build --pull -t travisghansen/external-auth-server:latest .
	docker push travisghansen/external-auth-server:latest
else
	:
fi
