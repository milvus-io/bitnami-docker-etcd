FROM docker.io/bitnami/minideb:bullseye

ARG TARGETARCH="linux/amd64"

LABEL maintainer="Team DevOps of Zilliz <devops@zilliz.com" \
      org.opencontainers.image.authors="https://bitnami.com/contact" \
      org.opencontainers.image.description="Application packaged by Bitnami, polished by zlliztech" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.ref.name="3.5.5-r4" \
      org.opencontainers.image.source="https://github.com/milvus-io/bitnami-docker-etcd" \
      org.opencontainers.image.title="etcd" \
      org.opencontainers.image.vendor="VMware, Inc." \
      org.opencontainers.image.version="3.5.5-r4"

ENV HOME="/" \
    OS_ARCH_RAW="${TARGETARCH}" \
    OS_FLAVOUR="debian-11" \
    OS_NAME="linux"

COPY prebuildfs /
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# Install required system packages and dependencies
RUN install_packages ca-certificates curl procps
RUN mkdir -p /tmp/bitnami/pkg/cache/ && cd /tmp/bitnami/pkg/cache/ && \
    OS_ARCH=`echo ${OS_ARCH_RAW}| sed 's|/|-|'` && \
    curl -SsLf https://github.com/etcd-io/etcd/releases/download/v3.5.5/etcd-v3.5.5-${OS_ARCH}.tar.gz -O && \
    tar -zxf "etcd-v3.5.5-${OS_ARCH}.tar.gz" && \
    mkdir -p /opt/bitnami/etcd/bin && \
    mv ./etcd-v3.5.5-${OS_ARCH}/etcd /opt/bitnami/etcd/bin/etcd && \
    mv ./etcd-v3.5.5-${OS_ARCH}/etcdctl /opt/bitnami/etcd/bin/etcdctl && \
    mv ./etcd-v3.5.5-${OS_ARCH}/etcdutl /opt/bitnami/etcd/bin/etcdutl && \
    rm -rf "etcd-v3.5.5-${OS_ARCH}.tar.gz"
RUN cd /tmp/bitnami/pkg/cache/ && \
    OS_ARCH=`echo ${OS_ARCH_RAW}| sed 's|/|-|'` && \
    COMPONENTS=( \
      "yq-4.40.5-0-${OS_ARCH}-debian-11" \
    ) && \
    for COMPONENT in "${COMPONENTS[@]}"; do \
      if [ ! -f "${COMPONENT}.tar.gz" ]; then \
        curl -SsLf "https://downloads.bitnami.com/files/stacksmith/${COMPONENT}.tar.gz" -O ; \
        curl -SsLf "https://downloads.bitnami.com/files/stacksmith/${COMPONENT}.tar.gz.sha256" -O ; \
      fi && \
      sha256sum -c "${COMPONENT}.tar.gz.sha256" && \
      tar -zxf "${COMPONENT}.tar.gz" -C /opt/bitnami --strip-components=2 --no-same-owner --wildcards '*/files' && \
      rm -rf "${COMPONENT}".tar.gz{,.sha256} ; \
    done
RUN apt-get autoremove --purge -y curl ca-certificates && \
    apt-get update && apt-get upgrade -y && \
    apt-get clean && rm -rf /var/lib/apt/lists /var/cache/apt/archives
RUN chmod g+rwX /opt/bitnami

COPY rootfs /
RUN /opt/bitnami/scripts/etcd/postunpack.sh
ENV APP_VERSION="3.5.5" \
    BITNAMI_APP_NAME="etcd" \
    ETCDCTL_API="3" \
    PATH="/opt/bitnami/common/bin:/opt/bitnami/etcd/bin:$PATH"

EXPOSE 2379 2380

WORKDIR /opt/bitnami/etcd
USER 1001
ENTRYPOINT [ "/opt/bitnami/scripts/etcd/entrypoint.sh" ]
CMD [ "/opt/bitnami/scripts/etcd/run.sh" ]
