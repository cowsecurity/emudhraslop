# Supply the exact application image, preferably an immutable digest.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
ARG TARGETARCH
# Set BINARY_TARGET=linux-arm-v7 when building a 32-bit ARM v7 image.
ARG BINARY_TARGET=linux-${TARGETARCH}
COPY --chmod=0555 dist/${BINARY_TARGET}/emudhraslop /usr/local/bin/emudhraslop
# Inherits the application image's USER. Do not grant privileges for scanning.
ENTRYPOINT ["/usr/local/bin/emudhraslop"]
CMD ["inventory", "--scope", "managed", "--json"]
