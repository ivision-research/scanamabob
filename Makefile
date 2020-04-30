init:
	pip install -r requirements.txt

infraup:
	pushd terraform && terraform init
	pushd terraform && terraform apply -auto-approve

infradown:
	pushd terraform && terraform destroy -auto-approve

test:
	py.test tests

.PHONY: init infraup infradown
