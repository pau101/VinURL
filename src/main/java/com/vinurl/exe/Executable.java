package com.vinurl.exe;

import org.apache.commons.lang3.SystemUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Flow;
import java.util.concurrent.SubmissionPublisher;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static com.vinurl.util.Constants.LOGGER;
import static com.vinurl.util.Constants.VINURLPATH;

public enum Executable {

	YT_DLP("yt-dlp", ExecutableInstaller.builder()
		.repository("yt-dlp/yt-dlp")
		.file("yt-dlp%s", "_linux", "_macos", ".exe")
		.verification(VerificationMethod.GPG_CHECKSUMS, "SHA2-256SUMS", "yt-dlp")),

	FFPROBE("ffprobe", ExecutableInstaller.builder()
		.repository("eugeneware/ffmpeg-static")
		.file("ffprobe-%s-x64", "linux", "darwin", "win32")
		.verification(VerificationMethod.GPG_TAG, null, "ffmpeg-static")),

	FFMPEG("ffmpeg", ExecutableInstaller.builder()
		.repository("eugeneware/ffmpeg-static")
		.file("ffmpeg-%s-x64", "linux", "darwin", "win32")
		.verification(VerificationMethod.GPG_TAG, null, "ffmpeg-static")),

	DENO("deno", ExecutableInstaller.builder()
		.repository("denoland/deno")
		.file("deno-x86_64-%s.zip", "unknown-linux-gnu", "apple-darwin", "pc-windows-msvc")
		.verification(VerificationMethod.GPG_COMMIT, null, "github"));

	private final Path directory = VINURLPATH.resolve("executables");
	private final Path filePath;
	private final VersionFile versionFile;
	private final ExecutableInstaller installer;
	private final ConcurrentHashMap<String, ProcessStream> activeProcesses = new ConcurrentHashMap<>();

	Executable(String fileName, ExecutableInstaller.Builder builder) {
		filePath = directory.resolve(fileName + (SystemUtils.IS_OS_WINDOWS ? ".exe" : ""));
		versionFile = new VersionFile(directory, fileName);
		installer = builder.build(fileName, directory, filePath, versionFile);
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

	public void checkForExecutable() {
		installer.checkAndInstall();
	}

	public UpdateResult checkForUpdates() {
		return installer.checkForUpdates(false);
	}

	public String currentVersion() {
		return versionFile.read();
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
					.command(Stream.concat(Stream.of(filePath.toString()), Stream.of(arguments)).toArray(String[]::new))
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