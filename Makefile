init:
	pip install -r requirements.txt

infraup:
	pushd terraform && terraform init
	pushd terraform && terraform apply -auto-approve

infradown:
	pushd terraform && terraform destroy -auto-approve

test:
	py.test tests

format:
	isort --multi-line=3 --trailing-comma --force-grid-wrap=0 --use-parentheses --line-width=88 -y
	black .

.PHONY: init infraup infradown
