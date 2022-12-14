.PHONY: all clean test cover travis lint

PROTO_FILES := $(shell find . -type f -name '*.proto')

release:
	@echo "Release v$(version)"
	@git pull
	@git checkout master
	@git pull
	@git checkout develop
	@git flow release start $(version)
	@git flow release finish $(version) -p -m "Release v$(version)"
	@git checkout develop
	@echo "Release v$(version) finished."

all: test

clean:
	@go clean -i ./...

coverage.out: $(shell find . -type f -print | grep -v vendor | grep "\.go")
	@go test -race -cover -coverprofile ./coverage.out.tmp -timeout 30s ./...
	@cat ./coverage.out.tmp | grep -v '.pb.go' | grep -v 'mock_' > ./coverage.out
	@rm ./coverage.out.tmp

test: coverage.out

lint:
	@golangci-lint run

cover: coverage.out
	@echo ""
	@go tool cover -func ./coverage.out


.PHONY: proto
proto: $(PROTO_FILES)
	@echo "Building $@..."
	@buf build
	@buf generate

cert:
	$(MAKE) -C ./certs
