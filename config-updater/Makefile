
.PHONY: all clean build warp_build warp_build_image warp_config_tree

all: clean build

clean:
	rm -rf build

build:
	env GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/linux/arm64/
	env GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/linux/amd64/
	env GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/darwin/arm64/
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/darwin/amd64/

warp_build:
	@echo "warp_build must be run through warpctl build so govulncheck gates image publication." >&2
	@false

# The config tree the image carries: the env's config with the shared all/
# files on top, under the version this build publishes.
#
# WARP_CONFIG_RESTART=no (`warpctl build --config_restart=no`) adds
# config-updater.yml, which tells the warpctl run worker that a block still on
# an older service version takes this config at its next deploy instead of
# restarting for it (holdConfigVersion in warpctl/run.go). A release passes it,
# since the rollout redeploys every block. Otherwise a new config version
# restarts running services, as it always has, and the file is absent.
warp_config_tree:
	rm -rf build/${WARP_ENV}/config/${WARP_VERSION}
	mkdir -p build/${WARP_ENV}/config
	cp -r ${WARP_CONFIG_HOME}/${WARP_ENV} build/${WARP_ENV}/config/${WARP_VERSION}
	cp -r ${WARP_CONFIG_HOME}/all/* build/${WARP_ENV}/config/${WARP_VERSION}/
	rm -f build/${WARP_ENV}/config/${WARP_VERSION}/config-updater.yml
	if [ "${WARP_CONFIG_RESTART}" = "no" ]; then \
		printf '# written by warpctl build --config_restart=no\nrestart: false\n' \
			> build/${WARP_ENV}/config/${WARP_VERSION}/config-updater.yml; \
	fi

warp_build_image: warp_config_tree
	docker buildx build --progress=plain \
		--build-arg warp_env=${WARP_ENV} \
		--platform linux/arm64/v8,linux/amd64 \
		-t ${WARP_DOCKER_NAMESPACE}/${WARP_DOCKER_IMAGE}:${WARP_DOCKER_VERSION} \
		--no-cache \
		--push \
		.
