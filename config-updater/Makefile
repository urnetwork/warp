
all: clean build

clean:
	rm -rf build

build:
	env GOOS=linux GOARCH=arm64 go build -o build/linux/arm64/
	env GOOS=linux GOARCH=amd64 go build -o build/linux/amd64/
	env GOOS=darwin GOARCH=arm64 go build -o build/darwin/arm64/
	env GOOS=darwin GOARCH=amd64 go build -o build/darwin/amd64/

warp_build:
	$(MAKE) clean
	$(MAKE) build
	mkdir -p build/${WARP_ENV}/config
	cp -r ${WARP_CONFIG_HOME}/${WARP_ENV} build/${WARP_ENV}/config/${WARP_VERSION}
	cp -r ${WARP_CONFIG_HOME}/all/* build/${WARP_ENV}/config/${WARP_VERSION}/

	docker buildx build --progress=plain \
		--build-arg warp_env=${WARP_ENV} \
		--platform linux/arm64/v8,linux/amd64 \
		-t ${WARP_DOCKER_NAMESPACE}/${WARP_DOCKER_IMAGE}:${WARP_DOCKER_VERSION} \
		--no-cache \
		--push \
		.
