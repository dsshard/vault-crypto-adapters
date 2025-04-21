.EXPORT_ALL_VARIABLES:

GO    = go
OS	  ="$(shell go env var GOOS | xargs)"
GOBIN =$(PWD)/.bin
path :=$(if $(path), $(path), "./")

version :=v0.0.3

.PHONY: lint
lint: ## Run linters
	$(info $(M) running linters...)
	golangci-lint run --timeout 5m0s ./...

.PHONY: build-linux-release
build-linux-release:  ## - build a static release linux elf(binary)
	@ CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -ldflags='-w -s -extldflags "-static"' -a -o "$(GOBIN)/release/linux/vault-crypto-adapters-$(version)"
	@ ls -lah $(GOBIN)/release/linux/vault-crypto-adapters-$(version)
	@ shasum -a 256 $(GOBIN)/release/linux/vault-crypto-adapters-$(version)
	@ mkdir -p ./.build/vault/plugins
	@ cp $(GOBIN)/release/linux/vault-crypto-adapters-$(version) ./.build/vault/plugins/vault-crypto-adapters-$(version)

.PHONY: build-common
build-common: ## - execute build common tasks clean and mod tidy
	@ $(GO) version
	@ $(GO) clean
	@ $(GO) mod tidy && $(GO) mod download
	@ $(GO) mod verify

.PHONY: test
test: ## - execute go test command
	@ go test ./...

build: build-common ## - build a debug binary to the current platform (windows, linux or darwin(mac))
	@ echo cleaning...
	@ rm -f $(GOBIN)/debug/$(OS)/vault-crypto-adapters
	@ echo building...
	@ $(GO) build -tags dev -o "$(GOBIN)/debug/$(OS)/vault-crypto-adapters"
	@ ls -lah $(GOBIN)/debug/$(OS)/vault-crypto-adapters
	@ shasum -a 256 $(GOBIN)/debug/$(OS)/vault-crypto-adapters

test-coverage: ## - execute go test command with coverage
	@ mkdir -p .coverage && mkdir -p .report
	@ go test -json -v -cover -covermode=atomic -coverprofile=.coverage/cover.out ./... > .report/report.out

