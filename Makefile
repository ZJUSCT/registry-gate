.PHONY: check format fmt-check vet test build chart-check

# The same checks CI runs (falcon-style: one entry point).
check: fmt-check vet test build chart-check

format: fmt-check
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	go vet ./...

test:
	go test ./...

build:
	go build ./...

# The chart's default values are an empty skeleton on purpose (required
# values must come from the environment), so lint/render against the
# minimal ci values.
chart-check:
	helm lint charts/registry-gate -f charts/registry-gate/ci/values.yaml
	helm template charts/registry-gate -f charts/registry-gate/ci/values.yaml >/dev/null
