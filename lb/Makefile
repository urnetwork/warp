
NGINX_COMMIT := 11d11b5f0d3d8ace5215e1a77918e9dc219ce7db
NGINX_SOURCE_SHA256 := dbc96585a7ddc6f3c3a8faae9487ecdf5ad4e1e2eeb77a8b26e69d935434c9de
NGINX_LOCAL_PREFIX := $(CURDIR)/build/nginx-local
# The pinned source's archive when one is already on this machine, used in
# place of the download and held to the same checksum.
NGINX_LOCAL_TARBALL ?=
# OpenSSL's compiler and linker flags, for a host whose headers are off the
# default path, e.g. NGINX_LOCAL_CC_OPT=-I/opt/homebrew/opt/openssl@3/include
# NGINX_LOCAL_LD_OPT=-L/opt/homebrew/opt/openssl@3/lib.
NGINX_LOCAL_CC_OPT ?=
NGINX_LOCAL_LD_OPT ?=

.PHONY: all clean build nginx_local warp_build warp_build_image

all: clean build

clean:
	rm -rf build

build:
	env GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/linux/arm64/
	env GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/linux/amd64/
	env GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/darwin/arm64/
	env GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=${WARP_VERSION}" -o build/darwin/amd64/

# Build the exact NGINX source used by the load-balancer image for local
# configuration, UDP upstream PROXY protocol v2 and SNI split tests: ssl,
# realip, stream ssl and ssl_preread for §13.4's split (TLS-M5-02), whose tests
# take this binary as NGINX_SPLIT_BINARY. The split's modules need OpenSSL's
# headers, which this build used to avoid, so it checks for them first and
# stops with what to install. It still needs no PCRE or zlib: the rewrite and
# gzip modules stay out.
nginx_local: $(NGINX_LOCAL_PREFIX)/sbin/nginx
	"$(NGINX_LOCAL_PREFIX)/sbin/nginx" -V

$(NGINX_LOCAL_PREFIX)/sbin/nginx: Makefile
	mkdir -p build/nginx-local-source
	@printf '#include <openssl/ssl.h>\nint main(void) { return OPENSSL_init_ssl(0, NULL) == 0; }\n' > build/nginx-local-source/openssl-check.c
	@$${CC:-cc} $(NGINX_LOCAL_CC_OPT) -c -o build/nginx-local-source/openssl-check.o build/nginx-local-source/openssl-check.c 2>/dev/null || { \
		echo "nginx_local builds ssl, realip and ssl_preread for the SNI split, which need OpenSSL's headers, and none were found." >&2; \
		echo "Install them (Debian: libssl-dev; macOS: brew install openssl@3), and pass their path where it is not the compiler's default:" >&2; \
		echo "  make nginx_local NGINX_LOCAL_CC_OPT=-I/opt/homebrew/opt/openssl@3/include NGINX_LOCAL_LD_OPT=-L/opt/homebrew/opt/openssl@3/lib" >&2; \
		exit 1; }
	@if [ -n "$(NGINX_LOCAL_TARBALL)" ]; then \
		cp "$(NGINX_LOCAL_TARBALL)" build/nginx-local-source/nginx.tar.gz; \
	else \
		curl --fail --location --retry 3 \
			--output build/nginx-local-source/nginx.tar.gz \
			"https://codeload.github.com/nginx/nginx/tar.gz/$(NGINX_COMMIT)"; \
	fi
	@if command -v sha256sum >/dev/null 2>&1; then \
		echo "$(NGINX_SOURCE_SHA256)  build/nginx-local-source/nginx.tar.gz" | sha256sum --check --strict; \
	else \
		echo "$(NGINX_SOURCE_SHA256)  build/nginx-local-source/nginx.tar.gz" | shasum -a 256 --check; \
	fi
	rm -rf build/nginx-local-source/nginx "$(NGINX_LOCAL_PREFIX)"
	mkdir -p build/nginx-local-source/nginx
	tar --extract --gzip \
		--file build/nginx-local-source/nginx.tar.gz \
		--directory build/nginx-local-source/nginx \
		--strip-components=1
	cd build/nginx-local-source/nginx && ./auto/configure \
		--build="urnetwork-$(NGINX_COMMIT)" \
		--prefix="$(NGINX_LOCAL_PREFIX)" \
		--with-stream \
		--with-http_ssl_module \
		--with-http_realip_module \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
		--with-cc-opt="$(NGINX_LOCAL_CC_OPT)" \
		--with-ld-opt="$(NGINX_LOCAL_LD_OPT)" \
		--without-http_rewrite_module \
		--without-http_gzip_module
	$(MAKE) -C build/nginx-local-source/nginx
	$(MAKE) -C build/nginx-local-source/nginx install

warp_build:
	@echo "warp_build must be run through warpctl build so govulncheck gates image publication." >&2
	@false

warp_build_image:
	# generate the config
	mkdir -p build/${WARP_ENV}/nginx.conf
	warpctl lb create-config ${WARP_ENV} --out=build/${WARP_ENV}/nginx.conf;
	echo "{\"version\":\"${WARP_VERSION}\",\"status\":\"ok\"}" > build/${WARP_ENV}/status.json
	# build the units for reference
	mkdir -p build/${WARP_ENV}/systemd
	warpctl service create-units ${WARP_ENV} --out=build/${WARP_ENV}/systemd;

	# --no-cache to always regenerate the encryption data
	# --progress=plain to Dockerfile command output
	docker buildx build --progress=plain \
		--build-arg warp_env=${WARP_ENV} \
		--platform linux/arm64/v8,linux/amd64 \
		-t ${WARP_DOCKER_NAMESPACE}/${WARP_DOCKER_IMAGE}:${WARP_DOCKER_VERSION} \
		--provenance=mode=max \
		--sbom=true \
		--no-cache \
		--push \
		.
