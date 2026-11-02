#!/usr/bin/env bash
set -euo pipefail

version=$1
package_version=$(uv version --short)
if [[ "$version" != "$package_version" || "$version" == *+* ]]; then
    echo "::error::Expected the exact public package version ($package_version)"
    exit 1
fi

if git show-ref --verify --quiet "refs/tags/v${version}"; then
    echo "::error::Tag v${version} already exists"
    exit 1
fi
