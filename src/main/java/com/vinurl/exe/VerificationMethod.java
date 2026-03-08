package com.vinurl.exe;

public enum VerificationMethod {
	// GPG signed checksums file (hash is signed by maintainer)
	GPG_CHECKSUMS,
	// GPG signed git tag (maintainer's key signs the release tag)
	GPG_TAG,
	// GPG signed commit (e.g. GitHub web-flow key)
	GPG_COMMIT,
	// GitHub API digest (fallback, unsigned)
	GITHUB_DIGEST
}
