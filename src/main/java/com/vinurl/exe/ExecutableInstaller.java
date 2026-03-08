package com.vinurl.exe;

import com.vinurl.exe.GitHub.ReleaseInfo;
import org.apache.commons.lang3.SystemUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.vinurl.client.VinURLClient.CONFIG;
import static com.vinurl.util.Constants.LOGGER;
import static java.nio.charset.StandardCharsets.UTF_8;

class ExecutableInstaller {
	private final String fileName;
	private final String repositoryName;
	private final String repositoryFile;
	private final VerificationMethod verificationMethod;
	private final String checksumsFile;
	private final String publicKeyName;
	private final Path directory;
	private final Path filePath;
	private final VersionFile versionFile;

	private ExecutableInstaller(String fileName, Builder builder, Path directory, Path filePath, VersionFile versionFile) {
		this.fileName = fileName;
		this.repositoryName = builder.repositoryName;
		this.repositoryFile = builder.repositoryFile;
		this.verificationMethod = builder.verificationMethod;
		this.checksumsFile = builder.checksumsFile;
		this.publicKeyName = builder.publicKeyName;
		this.directory = directory;
		this.filePath = filePath;
		this.versionFile = versionFile;
	}

	static Builder builder() {
		return new Builder();
	}

	static class Builder {
		private String repositoryName;
		private String repositoryFile;
		private VerificationMethod verificationMethod;
		private String checksumsFile;
		private String publicKeyName;

		Builder repository(String name) {
			this.repositoryName = name;
			return this;
		}

		Builder file(String pattern, String linux, String mac, String windows) {
			this.repositoryFile = pattern.formatted(
				SystemUtils.IS_OS_LINUX ? linux : SystemUtils.IS_OS_MAC ? mac : windows);
			return this;
		}

		Builder verification(VerificationMethod method, String checksumsFile, String publicKeyName) {
			this.verificationMethod = method;
			this.checksumsFile = checksumsFile;
			this.publicKeyName = publicKeyName;
			return this;
		}

		ExecutableInstaller build(String fileName, Path directory, Path filePath, VersionFile versionFile) {
			return new ExecutableInstaller(fileName, this, directory, filePath, versionFile);
		}
	}

	void checkAndInstall() {
		if (directory.toFile().exists() || directory.toFile().mkdirs()) {
			if (!filePath.toFile().exists()) {
				LOGGER.info("Executable {} not found, fetching latest release", fileName);
				ReleaseInfo release = GitHub.fetchLatestRelease(repositoryName, repositoryFile);
				if (release.isEmpty()) {
					LOGGER.warn("Could not fetch release info for {}", repositoryName);
				} else {
					install(release);
				}
			} else if (CONFIG.updatesOnStartup()) {
				checkForUpdates(true);
			}
		}
	}

	UpdateResult checkForUpdates(boolean requireGPG) {
		if (requireGPG && !canVerifyGPG()) {
			LOGGER.info("Auto-update skipped for {} (bouncycastle not available)", fileName);
			return UpdateResult.SKIPPED_NO_GPG;
		}
		ReleaseInfo release = GitHub.fetchLatestRelease(repositoryName, repositoryFile);
		String currentVersion = versionFile.read();
		if (release.isEmpty() || release.version().equals(currentVersion)) {
			return UpdateResult.UP_TO_DATE;
		}
		LOGGER.info("Update available for {}: {} -> {}", fileName, currentVersion, release.version());
		return install(release) ? UpdateResult.UPDATED : UpdateResult.FAILED;
	}

	private boolean canVerifyGPG() {
		return GPGVerifier.isAvailable() || verificationMethod == VerificationMethod.GITHUB_DIGEST;
	}

	private boolean install(ReleaseInfo release) {
		Path tempFile = null;
		try {
			String expectedHash = getExpectedHash(release);
			if (expectedHash == null) {
				return false;
			}

			tempFile = Files.createTempFile(directory, fileName, ".tmp");
			tempFile.toFile().deleteOnExit();

			String actualHash = downloadToFile(GitHub.openAssetStream(repositoryName, repositoryFile), tempFile);

			if (!expectedHash.equalsIgnoreCase(actualHash)) {
				LOGGER.error("Hash mismatch for {}, expected {} but got {}", repositoryFile, expectedHash, actualHash);
				return false;
			}

			if (repositoryFile.endsWith(".zip")) {
				extractFromZip(tempFile, filePath);
			} else {
				Files.move(tempFile, filePath, StandardCopyOption.REPLACE_EXISTING);
				tempFile = null;
			}

			if (SystemUtils.IS_OS_UNIX) {
				Runtime.getRuntime().exec(new String[] {"chmod", "+x", filePath.toString()});
			}
			LOGGER.info("Successfully installed {} version {}", fileName, release.version());
			return versionFile.write(release.version());
		} catch (Exception e) {
			LOGGER.error("Failed to download {}", repositoryFile, e);
			return false;
		} finally {
			if (tempFile != null) {
				try {
					Files.deleteIfExists(tempFile);
				} catch (IOException ignored) {}
			}
		}
	}

	private String getExpectedHash(ReleaseInfo release) {
		if (!GPGVerifier.isAvailable() && verificationMethod != VerificationMethod.GITHUB_DIGEST) {
			LOGGER.warn("Installing {} using GitHub digest (bouncycastle not available)", fileName);
			return release.digest();
		}

		return switch (verificationMethod) {
			case GPG_CHECKSUMS -> getGPGVerifiedHash();
			case GPG_TAG -> {
				if (!verifyTagSignature(release)) {
					yield null;
				}
				yield release.digest();
			}
			case GPG_COMMIT -> {
				if (!verifyCommitSignature(release)) {
					yield null;
				}
				yield release.digest();
			}
			case GITHUB_DIGEST -> release.digest();
		};
	}

	private boolean verifyTagSignature(ReleaseInfo release) {
		GitHub.Signature tagSig = release.tagSignature();
		if (!tagSig.isPresent()) {
			LOGGER.error("No tag signature found for {}, the tag may not be signed", repositoryName);
			return false;
		}
		return verifySignature(tagSig, "tag");
	}

	private boolean verifyCommitSignature(ReleaseInfo release) {
		GitHub.Signature commitSig = release.commitSignature();
		if (!commitSig.isPresent()) {
			LOGGER.error("No commit signature found for {}", repositoryName);
			return false;
		}
		return verifySignature(commitSig, "commit");
	}

	private boolean verifySignature(GitHub.Signature sig, String type) {
		try (InputStream keyStream = ExecutableInstaller.class.getResourceAsStream("/META-INF/vinurl/keys/" + publicKeyName + ".asc")) {
			if (keyStream == null) {
				LOGGER.error("Public key {} not found", publicKeyName);
				return false;
			}
			byte[] publicKey = keyStream.readAllBytes();
			byte[] signature = sig.signature().getBytes(UTF_8);
			byte[] payload = sig.payload().getBytes(UTF_8);

			if (!GPGVerifier.verifyDetachedSignature(payload, signature, publicKey)) {
				LOGGER.error("GPG {} signature verification failed for {}", type, repositoryName);
				return false;
			}
			return true;
		} catch (Exception e) {
			LOGGER.error("Error verifying {} signature for {}", type, repositoryName, e);
			return false;
		}
	}

	private String getGPGVerifiedHash() {
		try (InputStream checksumsStream = GitHub.openAssetStream(repositoryName, checksumsFile);
			 InputStream signatureStream = GitHub.openAssetStream(repositoryName, checksumsFile + ".sig");
			 InputStream keyStream = ExecutableInstaller.class.getResourceAsStream("/META-INF/vinurl/keys/" + publicKeyName + ".asc")) {

			if (keyStream == null) {
				LOGGER.error("Public key {} not found", publicKeyName);
				return null;
			}

			byte[] checksums = checksumsStream.readAllBytes();
			byte[] signature = signatureStream.readAllBytes();
			byte[] publicKey = keyStream.readAllBytes();

			if (!GPGVerifier.verifyDetachedSignature(checksums, signature, publicKey)) {
				LOGGER.error("GPG signature verification failed for checksums file {}", checksumsFile);
				return null;
			}

			String expectedHash = parseChecksumForFile(new String(checksums, UTF_8), repositoryFile);
			if (expectedHash == null) {
				LOGGER.error("Checksum for {} not found in {}", repositoryFile, checksumsFile);
				return null;
			}

			return "sha256:" + expectedHash.toLowerCase();
		} catch (Exception e) {
			LOGGER.error("Error verifying checksums for {}", repositoryFile, e);
			return null;
		}
	}

	private String parseChecksumForFile(String checksums, String fileName) {
		for (String line : checksums.split("\\R")) {
			String[] parts = line.trim().split("\\s+", 2);
			if (parts.length == 2) {
				String name = parts[1].startsWith("*") ? parts[1].substring(1) : parts[1];
				if (name.equals(fileName)) {
					return parts[0];
				}
			}
		}
		return null;
	}

	private String downloadToFile(InputStream input, Path target) throws IOException, NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		try (DigestInputStream digestInput = new DigestInputStream(input, md);
			 OutputStream output = Files.newOutputStream(target)) {
			digestInput.transferTo(output);
		}
		return "sha256:" + HexFormat.of().formatHex(md.digest());
	}

	private void extractFromZip(Path zipFile, Path target) throws IOException {
		String targetName = fileName + (SystemUtils.IS_OS_WINDOWS ? ".exe" : "");
		try (ZipInputStream zipInput = new ZipInputStream(Files.newInputStream(zipFile))) {
			ZipEntry zipEntry;
			while ((zipEntry = zipInput.getNextEntry()) != null) {
				if (zipEntry.getName().endsWith(targetName)) {
					Files.copy(zipInput, target, StandardCopyOption.REPLACE_EXISTING);
					return;
				}
			}
		}
		throw new IOException("Entry not found in zip: " + targetName);
	}

}
