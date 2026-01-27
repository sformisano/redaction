#!/bin/bash
set -euo pipefail

# Release script for redaction crates
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh 0.1.2

if [ $# -eq 0 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.2"
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"

# Validate version format (basic check)
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: Version must be in format X.Y.Z (e.g., 0.1.2)"
    exit 1
fi

echo "🚀 Preparing release ${TAG}..."

# Check if working directory is clean
if ! git diff-index --quiet HEAD --; then
    echo "Error: Working directory is not clean. Please commit or stash changes first."
    exit 1
fi

# Bump workspace version
echo "📝 Bumping workspace version to ${VERSION}..."
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml

# Update redaction-derive dependency version in redaction/Cargo.toml
echo "📝 Updating redaction-derive dependency version..."
sed -i '' "s/redaction-derive = { version = \".*\", path/redaction-derive = { version = \"${VERSION}\", path/" redaction/Cargo.toml

# Verify the changes
echo "✅ Version updated. Changes:"
git diff Cargo.toml redaction/Cargo.toml

# Commit the version bump
echo "📦 Committing version bump..."
git add Cargo.toml redaction/Cargo.toml
git commit -m "chore: bump version to ${VERSION}"

# Create tag
echo "🏷️  Creating tag ${TAG}..."
git tag -a "${TAG}" -m "Release ${TAG}"

# Push commits and tags
echo "📤 Pushing to remote..."
git push origin main
git push origin "${TAG}"

echo "✅ Release ${TAG} prepared and pushed!"
echo ""
echo "Next steps:"
echo "  - The GitHub Actions workflow will automatically publish to crates.io when it detects the tag"
echo "  - Or manually publish with: cargo publish -p redaction-derive && cargo publish -p redaction"
