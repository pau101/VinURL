package com.vinurl.exe;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.minecraft.client.Minecraft;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;

import static com.vinurl.util.Constants.MOD_ID;
import static com.vinurl.util.Constants.MOD_VERSION;

public class GitHub {
	private static final String USER_AGENT = "Java/%s %s/%s".formatted(System.getProperty("java.version"), MOD_ID, MOD_VERSION);
	private static final String API_VERSION = "2022-11-28";

	public record Signature(@Nullable String signature, @Nullable String payload) {
		public static final Signature EMPTY = new Signature(null, null);

		public boolean isPresent() {
			return signature != null && payload != null;
		}
	}

	public record ReleaseInfo(
		String version,
		@Nullable String digest,
		@Nullable String targetCommitSha,
		Signature tagSignature,
		Signature commitSignature
	) {
		public static final ReleaseInfo EMPTY = new ReleaseInfo("", null, null, Signature.EMPTY, Signature.EMPTY);

		public boolean isEmpty() {
			return version.isEmpty();
		}
	}

	public static ReleaseInfo fetchLatestRelease(String repository, String assetName) {
		String url = "https://api.github.com/repos/%s/releases/latest".formatted(repository);
		try (InputStream stream = openApiStream(url);
			 InputStreamReader reader = new InputStreamReader(stream)) {
			JsonObject release = JsonParser.parseReader(reader).getAsJsonObject();

			String version = release.get("tag_name").getAsString();
			String targetCommitish = release.get("target_commitish").getAsString();

			String digest = null;
			JsonArray assets = release.getAsJsonArray("assets");
			for (JsonElement asset : assets) {
				JsonObject assetObj = asset.getAsJsonObject();
				if (assetName.equals(assetObj.get("name").getAsString())) {
					JsonElement digestElement = assetObj.get("digest");
					if (digestElement != null && !digestElement.isJsonNull()) {
						digest = digestElement.getAsString();
					}
					break;
				}
			}

			Signature tagSig = fetchTagSignature(repository, version);
			Signature commitSig = fetchCommitSignature(repository, targetCommitish);

			return new ReleaseInfo(version, digest, targetCommitish, tagSig, commitSig);
		} catch (Exception e) {
			return ReleaseInfo.EMPTY;
		}
	}

	private static Signature fetchTagSignature(String repository, String tagName) {
		String refUrl = "https://api.github.com/repos/%s/git/ref/tags/%s".formatted(repository, tagName);
		try (InputStream refStream = openApiStream(refUrl);
			 InputStreamReader refReader = new InputStreamReader(refStream)) {
			JsonObject ref = JsonParser.parseReader(refReader).getAsJsonObject();
			JsonObject object = ref.getAsJsonObject("object");
			String type = object.get("type").getAsString();

			if (!"tag".equals(type)) {
				return Signature.EMPTY;
			}

			String tagSha = object.get("sha").getAsString();
			String tagUrl = "https://api.github.com/repos/%s/git/tags/%s".formatted(repository, tagSha);
			try (InputStream tagStream = openApiStream(tagUrl);
				 InputStreamReader tagReader = new InputStreamReader(tagStream)) {
				JsonObject tag = JsonParser.parseReader(tagReader).getAsJsonObject();
				JsonObject verification = tag.getAsJsonObject("verification");
				if (verification == null) {
					return Signature.EMPTY;
				}
				String signature = getStringOrNull(verification, "signature");
				String payload = getStringOrNull(verification, "payload");
				return new Signature(signature, payload);
			}
		} catch (Exception e) {
			return Signature.EMPTY;
		}
	}

	private static Signature fetchCommitSignature(String repository, String commitish) {
		String url = "https://api.github.com/repos/%s/commits/%s".formatted(repository, commitish);
		try (InputStream stream = openApiStream(url);
			 InputStreamReader reader = new InputStreamReader(stream)) {
			JsonObject commit = JsonParser.parseReader(reader).getAsJsonObject();
			JsonObject verification = commit.getAsJsonObject("commit").getAsJsonObject("verification");
			if (verification == null) {
				return Signature.EMPTY;
			}
			String signature = getStringOrNull(verification, "signature");
			String payload = getStringOrNull(verification, "payload");
			return new Signature(signature, payload);
		} catch (Exception e) {
			return Signature.EMPTY;
		}
	}

	private static @Nullable String getStringOrNull(JsonObject obj, String key) {
		JsonElement element = obj.get(key);
		return element != null && !element.isJsonNull() ? element.getAsString() : null;
	}

	public static InputStream openAssetStream(String repository, String assetName) throws IOException {
		String url = "https://github.com/%s/releases/latest/download/%s".formatted(repository, assetName);
		return openStream(url);
	}

	private static InputStream openApiStream(String url) throws IOException {
		HttpURLConnection conn = openConnection(url);
		conn.setRequestProperty("Accept", "application/vnd.github+json");
		conn.setRequestProperty("X-GitHub-Api-Version", API_VERSION);
		return conn.getInputStream();
	}

	private static InputStream openStream(String url) throws IOException {
		return openConnection(url).getInputStream();
	}

	private static HttpURLConnection openConnection(String url) throws IOException {
		try {
			HttpURLConnection conn = (HttpURLConnection) new URI(url).toURL().openConnection(Minecraft.getInstance().getProxy());
			conn.setRequestProperty("User-Agent", USER_AGENT);
			return conn;
		} catch (URISyntaxException e) {
			throw new IOException("Invalid URL: " + url, e);
		}
	}
}
