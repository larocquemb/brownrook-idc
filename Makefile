APP=brownrook-idc
IMAGE=localhost/brownrook-idc:0.1
PORT=8080

.PHONY: dev build run test validate validate-k8s smoke-kind clean

dev:
	uvicorn brownrook_idc.main:app --reload --host 127.0.0.1 --port $(PORT)

build:
	podman build -t $(IMAGE) .

run:
	podman run --rm -p $(PORT):8080 --env-file .env $(IMAGE)

test:
	pytest

validate: test validate-k8s

validate-k8s:
	./scripts/validate_kubernetes.sh

smoke-kind:
	./scripts/kind_smoke.sh

clean:
	rm -rf build dist *.egg-info
