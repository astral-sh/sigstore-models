# sigstore-models

![PyPI - Version](https://img.shields.io/pypi/v/sigstore-models)

Pydantic-based data models for Sigstore.

These models mirror the subset of the [protobuf-specs] that
are used by the [sigstore-python] library.

## Goals

* Providing high-quality, type-safe data models to [sigstore-python].
* Matching Sigstore's (mostly protobuf influenced) JSON serialization
  format.

## Anti-goals

* Supporting protobuf serialization/deserialization.
* Doing anything besides mirroring a subset of the types in
  [protobuf-specs].

[protobuf-specs]: https://github.com/sigstore/protobuf-specs
[sigstore-python]: https://github.com/sigstore/sigstore-python
