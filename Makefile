APP=brownrook-idc
IMAGE=localhost/brownrook-idc:0.1
PORT=8080

.PHONY: dev build run test clean

dev:
	uvicorn brownrook_idc.main:app --reload --host 127.0.0.1 --port $(PORT)

build:
	podman build -t $(IMAGE) .

run:
	podman run --rm -p $(PORT):8080 --env-file .env $(IMAGE)

test:
	pytest

clean:
	rm -rf build dist *.egg-info
