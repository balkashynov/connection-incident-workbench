.PHONY: build test lab
build:
	go build -trimpath -o bin/connection-workbench ./cmd/connection-workbench
test:
	go test -race ./...
	go vet ./...
lab: build
	python3 lab/build.py
	python3 lab/run.py

.PHONY: demo
demo: build
	python3 scripts/demo.py

.PHONY: web-demo
web-demo: build
	python3 scripts/build_demo.py
