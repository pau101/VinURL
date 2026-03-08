package com.vinurl.exe;

import org.apache.commons.lang3.SystemUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Flow;
import java.util.concurrent.SubmissionPublisher;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.vinurl.client.VinURLClient.CONFIG;
import static com.vinurl.exe.GitHub.ReleaseInfo;
import static com.vinurl.util.Constants.LOGGER;
import static com.vinurl.util.Constants.VINURLPATH;
import static java.nio.charset.StandardCharsets.UTF_8;

public enum Executable {

	YT_DLP("yt-dlp", "yt-dlp/yt-dlp", "yt-dlp%s".formatted(
		SystemUtils.IS_OS_LINUX ? "_linux" : SystemUtils.IS_OS_MAC ? "_macos" : ".exe"),
		VerificationMethod.GPG_CHECKSUMS, "SHA2-256SUMS", "yt-dlp"),
	FFPROBE("ffprobe", "eugeneware/ffmpeg-static", "ffprobe-%s-x64".formatted(
		SystemUtils.IS_OS_LINUX ? "linux" : SystemUtils.IS_OS_MAC ? "darwin" : "win32"),
		VerificationMethod.GPG_TAG, null, "ffmpeg-static"),
	FFMPEG("ffmpeg", "eugeneware/ffmpeg-static", "ffmpeg-%s-x64".formatted(
		SystemUtils.IS_OS_LINUX ? "linux" : SystemUtils.IS_OS_MAC ? "darwin" : "win32"),
		VerificationMethod.GPG_TAG, null, "ffmpeg-static"),
	DENO("deno", "denoland/deno", "deno-x86_64-%s.zip".formatted(
		SystemUtils.IS_OS_LINUX ? "unknown-linux-gnu" : SystemUtils.IS_OS_MAC ? "apple-darwin" : "pc-windows-msvc"),
		VerificationMethod.GPG_COMMIT, null, "github");

	public final Path DIRECTORY = VINURLPATH.resolve("executables");
	private final String FILE_NAME;
	private final String REPOSITORY_NAME;
	private final String REPOSITORY_FILE;
	private final VerificationMethod VERIFICATION_METHOD;
	private final String CHECKSUMS_FILE;
	private final String PUBLIC_KEY_NAME;
	private final Path FILE_PATH;
	private final Path VERSION_PATH;
	private final ConcurrentHashMap<String, ProcessStream> activeProcesses = new ConcurrentHashMap<>();

	Executable(String fileName, String repositoryName, String repositoryFile,
			   VerificationMethod verificationMethod, String checksumsFile, String publicKeyName) {
		FILE_NAME = fileName;
		REPOSITORY_NAME = repositoryName;
		REPOSITORY_FILE = repositoryFile;
		VERIFICATION_METHOD = verificationMethod;
		CHECKSUMS_FILE = checksumsFile;
		PUBLIC_KEY_NAME = publicKeyName;
		FILE_PATH = DIRECTORY.resolve(FILE_NAME + (SystemUtils.IS_OS_WINDOWS ? ".exe" : ""));
		VERSION_PATH = DIRECTORY.resolve(FILE_NAME + ".version");
	}

	public boolean registerProcess(String id, ProcessStream processStream) {
		return activeProcesses.computeIfAbsent(id, (s) -> {
			processStream.onExit(() -> activeProcesses.remove(id));
			return processStream;
		}) == processStream;
	}

	public boolean isProcessRunning(String id) {
		return activeProcesses.containsKey(id);
	}

	public ProcessStream getProcessStream(String id) {
		return activeProcesses.get(id);
	}

	public void killProcess(String id) {
		ProcessStream stream = activeProcesses.remove(id);
		if (stream != null && stream.process != null) {
			try {
				stream.process.descendants().forEach((processHandle) -> {
					processHandle.destroyForcibly();
					processHandle.onExit().join();
				});
				stream.process.destroyForcibly();
				stream.process.onExit().join();
			} catch (Exception e) {
				LOGGER.error("Failed to kill process with ID: {}", id, e);
			}
		}
	}

	public void killAllProcesses() {
		for (String id : Set.copyOf(activeProcesses.keySet())) {
			killProcess(id);
		}
	}

	public boolean checkForExecutable() {
		if (DIRECTORY.toFile().exists() || DIRECTORY.toFile().mkdirs()) {
			if (!FILE_PATH.toFile().exists()) {
				LOGGER.info("Executable {} not found, fetching latest release", FILE_NAME);
				ReleaseInfo release = GitHub.fetchLatestRelease(REPOSITORY_NAME, REPOSITORY_FILE);
				if (release.isEmpty()) {
					LOGGER.warn("Could not fetch release info for {}", REPOSITORY_NAME);
					return false;
				}
				return downloadExecutable(release, false);
			} else if (CONFIG.updatesOnStartup()) {
				checkForUpdates();
			}
			return true;
		}
		return false;
	}

	public boolean checkForUpdates() {
		if (!canVerifyGPG()) {
			LOGGER.debug("Skipping update check for {} because GPG verification is unavailable", FILE_NAME);
			return false;
		}
		ReleaseInfo release = GitHub.fetchLatestRelease(REPOSITORY_NAME, REPOSITORY_FILE);
		if (release.isEmpty() || release.version().equals(currentVersion())) {
			return false;
		}
		LOGGER.info("Update available for {}: {} -> {}", FILE_NAME, currentVersion(), release.version());
		return downloadExecutable(release, true);
	}

	private boolean canVerifyGPG() {
		return GPGVerifier.isAvailable() || VERIFICATION_METHOD == VerificationMethod.GITHUB_DIGEST;
	}

	private boolean downloadExecutable(ReleaseInfo release, boolean requireGPG) {
		Path tempFile = null;
		try {
			String expectedHash = getExpectedHash(release, requireGPG);
			if (expectedHash == null) {
				return false;
			}

			tempFile = Files.createTempFile(DIRECTORY, FILE_NAME, ".tmp");
			tempFile.toFile().deleteOnExit();

			String actualHash = downloadToFile(GitHub.openAssetStream(REPOSITORY_NAME, REPOSITORY_FILE), tempFile);

			if (!expectedHash.equalsIgnoreCase(actualHash)) {
				LOGGER.error("Hash mismatch for {}, expected {} but got {}", REPOSITORY_FILE, expectedHash, actualHash);
				return false;
			}

			if (REPOSITORY_FILE.endsWith(".zip")) {
				extractFromZip(tempFile, FILE_PATH);
			} else {
				Files.move(tempFile, FILE_PATH, StandardCopyOption.REPLACE_EXISTING);
				tempFile = null;
			}

			if (SystemUtils.IS_OS_UNIX) {
				Runtime.getRuntime().exec(new String[] {"chmod", "+x", FILE_PATH.toString()});
			}
			LOGGER.info("Successfully installed {} version {}", FILE_NAME, release.version());
			return createVersionFile(release.version());
		} catch (Exception e) {
			LOGGER.error("Failed to download {}", REPOSITORY_FILE, e);
			return false;
		} finally {
			if (tempFile != null) {
				try {
					Files.deleteIfExists(tempFile);
				} catch (IOException ignored) {}
			}
		}
	}

	private String getExpectedHash(ReleaseInfo release, boolean requireGPG) {
		if (!GPGVerifier.isAvailable() && VERIFICATION_METHOD != VerificationMethod.GITHUB_DIGEST) {
			if (requireGPG) {
				LOGGER.error("Cannot update {} because GPG verification is unavailable", FILE_NAME);
				return null;
			}
			LOGGER.warn("GPG verification unavailable, using GitHub digest for initial download of {}", FILE_NAME);
			return release.digest();
		}

		return switch (VERIFICATION_METHOD) {
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
			LOGGER.error("No tag signature found for {}, the tag may not be signed", REPOSITORY_NAME);
			return false;
		}
		return verifySignature(tagSig, "tag");
	}

	private boolean verifyCommitSignature(ReleaseInfo release) {
		GitHub.Signature commitSig = release.commitSignature();
		if (!commitSig.isPresent()) {
			LOGGER.error("No commit signature found for {}", REPOSITORY_NAME);
			return false;
		}
		return verifySignature(commitSig, "commit");
	}

	private boolean verifySignature(GitHub.Signature sig, String type) {
		try (InputStream keyStream = Executable.class.getResourceAsStream("/META-INF/vinurl/keys/" + PUBLIC_KEY_NAME + ".asc")) {
			if (keyStream == null) {
				LOGGER.error("Public key {} not found", PUBLIC_KEY_NAME);
				return false;
			}
			byte[] publicKey = keyStream.readAllBytes();
			byte[] signature = sig.signature().getBytes(UTF_8);
			byte[] payload = sig.payload().getBytes(UTF_8);

			if (!GPGVerifier.verifyDetachedSignature(payload, signature, publicKey)) {
				LOGGER.error("GPG {} signature verification failed for {}", type, REPOSITORY_NAME);
				return false;
			}
			return true;
		} catch (Exception e) {
			LOGGER.error("Error verifying {} signature for {}", type, REPOSITORY_NAME, e);
			return false;
		}
	}

	private String getGPGVerifiedHash() {
		try (InputStream checksumsStream = GitHub.openAssetStream(REPOSITORY_NAME, CHECKSUMS_FILE);
			 InputStream signatureStream = GitHub.openAssetStream(REPOSITORY_NAME, CHECKSUMS_FILE + ".sig");
			 InputStream keyStream = Executable.class.getResourceAsStream("/META-INF/vinurl/keys/" + PUBLIC_KEY_NAME + ".asc")) {

			if (keyStream == null) {
				LOGGER.error("Public key {} not found", PUBLIC_KEY_NAME);
				return null;
			}

			byte[] checksums = checksumsStream.readAllBytes();
			byte[] signature = signatureStream.readAllBytes();
			byte[] publicKey = keyStream.readAllBytes();

			if (!GPGVerifier.verifyDetachedSignature(checksums, signature, publicKey)) {
				LOGGER.error("GPG signature verification failed for checksums file {}", CHECKSUMS_FILE);
				return null;
			}

			String expectedHash = parseChecksumForFile(new String(checksums, UTF_8), REPOSITORY_FILE);
			if (expectedHash == null) {
				LOGGER.error("Checksum for {} not found in {}", REPOSITORY_FILE, CHECKSUMS_FILE);
				return null;
			}

			return "sha256:" + expectedHash.toLowerCase();
		} catch (Exception e) {
			LOGGER.error("Error verifying checksums for {}", REPOSITORY_FILE, e);
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
		String targetName = FILE_NAME + (SystemUtils.IS_OS_WINDOWS ? ".exe" : "");
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

	private boolean createVersionFile(String version) {
		try {
			Files.writeString(VERSION_PATH, version);
			return true;
		} catch (IOException ignored) {
			return false;
		}
	}

	public String currentVersion() {
		try {
			return Files.readString(VERSION_PATH);
		} catch (IOException e) {
			return "";
		}
	}

	public ProcessStream executeCommand(String id, String... arguments) {
		return new ProcessStream(id, arguments);
	}

	public class ProcessStream {
		private final String id;
		private final String[] arguments;
		private final SubmissionPublisher<String> publisher = new SubmissionPublisher<>();
		private final ConcurrentHashMap<String, Flow.Subscription> subscriptions = new ConcurrentHashMap<>();
		private Process process;

		public ProcessStream(String id, String... arguments) {
			this.id = id;
			this.arguments = arguments;
			if (registerProcess(id, this)) {
				CompletableFuture.runAsync(this::startProcess);
			}
		}

		public String getId() {
			return id;
		}

		public SubscriberBuilder subscribe(String subscriberId) {
			return new SubscriberBuilder(subscriberId);
		}

		public void unsubscribe(String subscriberId) {
			Flow.Subscription subscription = subscriptions.remove(subscriberId);
			if (subscription != null) {
				subscription.cancel();
			}
		}

		public int subscriberCount() {
			return subscriptions.size();
		}

		public void onExit(Runnable callback) {
			if (process != null) {
				process.onExit().thenRun(() -> {
					subscriptions.keySet().forEach(this::unsubscribe);
					callback.run();
				});
			}
		}

		private void startProcess() {
			try {
				process = new ProcessBuilder()
					.command(Stream.concat(Stream.of(FILE_PATH.toString()), Stream.of(arguments)).toArray(String[]::new))
					.redirectErrorStream(true)
					.start();

				try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
					String line;
					while ((line = reader.readLine()) != null && !publisher.isClosed()) {
						publisher.submit(line);
					}
				}

				int exitCode = process.waitFor();

				if (exitCode == 0) {
					publisher.close();
				} else {
					publisher.closeExceptionally(new IOException("Process failed with code: " + exitCode));
				}
			} catch (IOException | InterruptedException e) {
				publisher.closeExceptionally(e);
			} finally {
				killProcess(id);
			}
		}

		public class SubscriberBuilder {
			private final String subscriberId;
			private Consumer<String> onOutput = (s) -> {};
			private Consumer<Throwable> onError = (t) -> {};
			private Runnable onComplete = () -> {};

			public SubscriberBuilder(String subscriberId) {
				this.subscriberId = subscriberId;
			}

			public SubscriberBuilder onOutput(Consumer<String> consumer) {
				this.onOutput = consumer;
				return this;
			}

			public SubscriberBuilder onError(Consumer<Throwable> consumer) {
				this.onError = consumer;
				return this;
			}

			public SubscriberBuilder onComplete(Runnable runnable) {
				this.onComplete = runnable;
				return this;
			}

			public void start() {
				publisher.subscribe(new Flow.Subscriber<>() {
					@Override
					public void onSubscribe(Flow.Subscription subscription) {
						subscriptions.put(subscriberId, subscription);
						subscription.request(Long.MAX_VALUE);
					}

					@Override
					public void onNext(String item) {
						onOutput.accept(item);
					}

					@Override
					public void onError(Throwable throwable) {
						subscriptions.remove(subscriberId);
						onError.accept(throwable);
					}

					@Override
					public void onComplete() {
						subscriptions.remove(subscriberId);
						onComplete.run();
					}
				});
			}
		}
	}
}