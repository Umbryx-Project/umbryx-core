#!/usr/bin/env bash
set -euo pipefail

REGISTRY="${1:-umbryx}"
TAG="${2:-latest}"
PUSH_REGISTRY="${3:-}"

echo "=== Building Umbryx infrastructure images ==="

build() {
    local name=$1
    echo ""
    echo "--- $name ---"
    docker build -t "${REGISTRY}/${name}:${TAG}" \
        -f "docker/images/${name}/Dockerfile" \
        --network=host \
        .
    echo "OK: ${REGISTRY}/${name}:${TAG}"
}

build "adaptix" &
build "sliver" &
build "evilginx2" &
build "iodine" &
build "covenant" &
build "mythic" &
build "pwndrop" &
build "ligolo" &

wait

echo ""
echo "=== All images built ==="
docker images "${REGISTRY}/*" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

if [ -n "$PUSH_REGISTRY" ]; then
    echo ""
    echo "=== Pushing to ${PUSH_REGISTRY} ==="
    for name in adaptix sliver evilginx2 iodine covenant mythic pwndrop ligolo; do
        local_tag="${REGISTRY}/${name}:${TAG}"
        remote_tag="${PUSH_REGISTRY}/${name}:${TAG}"
        docker tag "$local_tag" "$remote_tag"
        docker push "$remote_tag"
        echo "Pushed: $remote_tag"
    done
fi

echo ""
echo "Done. Images ready for K8s deployment via Instance Pool."
