# cloud-vpn-protobuf

This repository does two things for us:

* It contains the protobuf files for the cloud-vpn project.
* It also generates the base image used by the [cloud-vpn-strongswan](https://github.office.opendns.com/slvpn/cloud-vpn-strongswan.git) build.

### Protobuf Code Generation

This repository contains the protobuf files. It will generate appropriate code for users of these protobufs, currently focused on generating C code and python bindings.

In the future, all data stored in our key/value store will be stored as a
protobuf.

### Base Image For cloud-vpn-strongswan

The base image is generated in the form of a Docker container which is pushed to the Quaddra docker registry and consumed by the concourse pipeline for the cloud-vpn-strongswan repository.

While the base image contains the protobuf code, the underlying Debian base build image is also used by cloud-vpn-strongswan even though the protobuf code is currently not consumed as of 2019-04-16.
