
all: init clean build

clean:
	rm -rf build

build:
	env GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/linux/arm64/
	env GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/linux/amd64/
	env GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/darwin/arm64/
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/darwin/amd64/

init:
	go clean -cache
	go clean -modcache

warp_build:
	$(MAKE) all
	# generate the config
	mkdir -p build/${WARP_ENV}/nginx.conf
	warpctl lb create-config ${WARP_ENV} --out=build/${WARP_ENV}/nginx.conf;
	echo "{\"version\":\"${WARP_VERSION}\",\"status\":\"ok\"}" > build/${WARP_ENV}/status.json
	# build the units for reference
	mkdir -p build/${WARP_ENV}/systemd
	warpctl service create-units ${WARP_ENV} --out=build/${WARP_ENV}/systemd;
	# version the build for reference so that we can track changes
	if [[ -e ../../xops/lb ]]; then\
		rm -rf ../../xops/lb/${WARP_ENV};\
		cp -r build/${WARP_ENV} ../../xops/lb/${WARP_ENV};\
	fi

	# --no-cache to always regenerate the encryption data
	# --progress=plain to Dockerfile command output
	docker buildx build --progress=plain \
		--build-arg warp_env=${WARP_ENV} \
		--platform linux/arm64/v8,linux/amd64 \
		-t ${WARP_DOCKER_NAMESPACE}/${WARP_DOCKER_IMAGE}:${WARP_DOCKER_VERSION} \
		--no-cache \
		--push \
		.
