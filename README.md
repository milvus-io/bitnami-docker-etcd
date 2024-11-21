# Etcd packaged by Bitnami, polished by milvus.io community

# Why we forked this repo?

The original repo is `bitnami/bitnami-docker-etcd` which is moved to `bitnami/containers`. 

We forked this repo at first to fix some bugs. And then we polished it to make it more stable for kuberentes. Some features may not be adapted by bitnami in a short time, but we need it in our release. So we forked it and will maintain it by ourselves. Thanks for bitnami's great work.

## TL;DR

```console
$ docker run -it --name Etcd milvus-io/etcd
```

## Prerequisites

To run this application you need [Docker Engine](https://www.docker.com/products/docker-engine) >= `1.10.0`. [Docker Compose](https://docs.docker.com/compose/) is recommended with a version `1.6.0` or later.

## Get this image

The recommended way to get the Bitnami Etcd Docker Image is to pull the prebuilt image from the [Docker Hub Registry](https://hub.docker.com/r/bitnami/etcd).

```console
$ docker pull milvusdb/etcd:latest
```

To use a specific version, you can pull a versioned tag. You can view the
[list of available versions](https://hub.docker.com/r/bitnami/etcd/tags/)
in the Docker Hub Registry.

```console
$ docker pull milvusdb/etcd:[TAG]
```

## License

Copyright &copy; 2022 Bitnami

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
