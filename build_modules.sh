#!/bin/bash
# Build script for Worker 3 module Docker images
# Builds all per-module containers or a specific module if specified
#
# Usage:
#   ./build_modules.sh                    # Build all modules
#   ./build_modules.sh -l                 # List available modules
#   ./build_modules.sh osint_domains_curl # Build specific module
#   ./build_modules.sh osint_domains_amass # Build specific module

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE_REGISTRY=${IMAGE_REGISTRY:-orchestrator}
SPECIFIC_MODULE=$1  # Optional: module name to build or -l flag

# Check if -l flag is used to list available modules
if [ "$SPECIFIC_MODULE" = "-l" ]; then
    echo "=========================================="
    echo "Available Worker 3 Modules"
    echo "=========================================="
    echo ""
    find . -name "Dockerfile" -exec dirname {} \; | xargs -n1 basename | sort | sed 's/^/    - /'
    echo ""
    echo "=========================================="
    echo "Total: $(find . -name "Dockerfile" | wc -l) module(s)"
    echo "=========================================="
    exit 0
fi

echo "=========================================="
echo "Building Worker 3 Module Images"
echo "Image Registry: ${IMAGE_REGISTRY}"
if [ -n "$SPECIFIC_MODULE" ]; then
    echo "Building module: ${SPECIFIC_MODULE}"
else
    echo "Building all modules"
fi
echo "=========================================="
echo ""

# Find all Dockerfiles in modules
if [ -n "$SPECIFIC_MODULE" ]; then
    # Build specific module - search recursively in all subdirectories
    DOCKERFILES=$(find . -type d -name "${SPECIFIC_MODULE}" -exec find {} -name "Dockerfile" \; | head -1)
    if [ -z "$DOCKERFILES" ]; then
        echo "[X] Module '${SPECIFIC_MODULE}' not found"
        echo ""
        echo "Available modules:"
        find . -name "Dockerfile" -exec dirname {} \; | xargs -n1 basename | sed 's/^/    - /'
        exit 1
    fi
else
    # Build all modules
    DOCKERFILES=$(find . -name "Dockerfile" | sort)
fi

if [ -z "$DOCKERFILES" ]; then
    echo "[X] No Dockerfiles found"
    exit 1
fi

if [ -n "$SPECIFIC_MODULE" ]; then
    echo "Found 1 module Dockerfile"
else
    echo "Found $(echo "$DOCKERFILES" | wc -l) module Dockerfiles"
fi
echo ""

# Build each module image
for dockerfile in $DOCKERFILES; do
    module_dir=$(dirname "$dockerfile")
    module_name=$(basename "$module_dir")
    
    # Determine image name
    image_name="${IMAGE_REGISTRY}/${module_name}:latest"
    
    echo "Building: $image_name"
    echo "  Dockerfile: $dockerfile"
    
    # Build the image - use current directory (modules/) as build context
    if docker build --no-cache -f "$dockerfile" -t "$image_name" .; then
        echo "  [OK] Built successfully"
    else
        echo "  [X] Build failed"
        exit 1
    fi
    echo ""
done

echo "=========================================="
if [ -n "$SPECIFIC_MODULE" ]; then
    echo "[OK] Module '${SPECIFIC_MODULE}' built successfully!"
else
    echo "[OK] All module images built successfully!"
fi
echo "=========================================="
echo ""
echo "Built images:"
docker images | grep "${IMAGE_REGISTRY}/" | head -20

