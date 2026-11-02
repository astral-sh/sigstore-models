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

## Releasing

1. Run [Prepare release] from `main` with the exact package version, such as
   `0.1.0` or `0.1.0rc1`.
2. Review and merge the release PR.
3. Run [Release] from `main` with the same version.

The `pypi.org` GitHub environment must allow deployments from the `main` branch.

[protobuf-specs]: https://github.com/sigstore/protobuf-specs
[sigstore-python]: https://github.com/sigstore/sigstore-python
[Prepare release]: https://github.com/astral-sh/sigstore-models/actions/workflows/release-prepare.yml
[Release]: https://github.com/astral-sh/sigstore-models/actions/workflows/publish.yml
