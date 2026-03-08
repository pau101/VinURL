package com.vinurl.exe;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

class VersionFile {
	private final Path path;

	VersionFile(Path directory, String fileName) {
		this.path = directory.resolve(fileName + ".version");
	}

	String read() {
		try {
			return Files.readString(path);
		} catch (IOException e) {
			return "";
		}
	}

	boolean write(String version) {
		try {
			Files.writeString(path, version);
			return true;
		} catch (IOException ignored) {
			return false;
		}
	}
}
