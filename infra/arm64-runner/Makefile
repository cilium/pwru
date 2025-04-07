SHELL := /bin/bash

.PHONY: plan apply destroy init

init:
	terraform init --upgrade \
			-backend-config=region=$(STATE_REGION) \
			-backend-config=bucket=$(STATE_BUCKET) \
			-backend-config=key=$(STATE_FILE)

plan: init
	terraform plan

apply: AUTO_APPROVE ?= false
apply: init
	terraform apply --auto-approve=$(AUTO_APPROVE)

destroy: AUTO_APPROVE ?= false
destroy: init
	terraform destroy --auto-approve=$(AUTO_APPROVE)
