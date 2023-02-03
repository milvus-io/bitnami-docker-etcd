FROM docker.io/bitnami/minideb:buster
LABEL maintainer "Bitnami <containers@bitnami.com>"

ENV HOME="/" \
    OS_ARCH="amd64" \
    OS_FLAVOUR="debian-10" \
    OS_NAME="linux"

COPY prebuildfs /

# Install required system packages and dependencies

# check from https://downloads.bitnami.com/files/stacksmith/${COMPONENT}.tar.gz.sha256
# COMPONENTS=( \
#       "yq-4.30.8-1-linux-${OS_ARCH}-debian-11" \
#       "gosu-1.16.0-1-linux-${OS_ARCH}-debian-11" \
#       "etcd-3.5.5-2-linux-${OS_ARCH}-debian-11" \
#     )
# OS_ARCH="${TARGETARCH:-amd64}
RUN install_packages acl ca-certificates curl gzip procps tar
RUN . /opt/bitnami/scripts/libcomponent.sh && component_unpack "yq" "4.30.8-1" --checksum 33fec06619aa3c1f7ea3c2516bf36f79af01354972ff06998ca6fe1d65078998
RUN . /opt/bitnami/scripts/libcomponent.sh && component_unpack "gosu" "1.16.0-1" --checksum 9ab9654690d90d3c49ff66fb1eb286487e318adc899d036bc45922f6b176865b
RUN . /opt/bitnami/scripts/libcomponent.sh && component_unpack "etcd" "3.5.5-2" --checksum 83cb31342af4b898223f50af4bfa5a7f206450547854601331e1855ac1c2798d
RUN apt-get update && apt-get upgrade -y && \
    rm -r /var/lib/apt/lists /var/cache/apt/archives
RUN chmod g+rwX /opt/bitnami

COPY rootfs /
RUN /opt/bitnami/scripts/etcd/postunpack.sh
ENV APP_VERSION="3.5.5" \
    BITNAMI_APP_NAME="etcd" \
    PATH="/opt/bitnami/common/bin:/opt/bitnami/etcd/bin:$PATH"

EXPOSE 2379 2380

WORKDIR /opt/bitnami/etcd
USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/etcd/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/etcd/run.sh" ]
