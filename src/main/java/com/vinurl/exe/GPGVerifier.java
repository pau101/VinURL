package com.vinurl.exe;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

import java.io.ByteArrayInputStream;
import java.security.Security;

import static com.vinurl.util.Constants.LOGGER;

public final class GPGVerifier {
	private static final boolean AVAILABLE;

	static {
		boolean available = false;
		try {
			if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
				Security.addProvider(new BouncyCastleProvider());
			}
			available = true;
		} catch (NoClassDefFoundError ignored) {}
		AVAILABLE = available;
	}

	private GPGVerifier() {}

	public static boolean isAvailable() {
		return AVAILABLE;
	}

	public static boolean verifyDetachedSignature(byte[] data, byte[] signature, byte[] publicKey) {
		if (!AVAILABLE) {
			return false;
		}
		try {
			return doVerify(data, signature, publicKey);
		} catch (Exception e) {
			LOGGER.error("Error during GPG signature verification", e);
			return false;
		}
	}

	private static boolean doVerify(byte[] data, byte[] signature, byte[] publicKey) throws Exception {
		var keyRings = new BcPGPPublicKeyRingCollection(
			PGPUtil.getDecoderStream(new ByteArrayInputStream(publicKey))
		);

		var sigFactory = new BcPGPObjectFactory(
			PGPUtil.getDecoderStream(new ByteArrayInputStream(signature))
		);

		Object obj = sigFactory.nextObject();
		PGPSignatureList sigList = obj instanceof PGPCompressedData compressed
			? (PGPSignatureList) new BcPGPObjectFactory(compressed.getDataStream()).nextObject()
			: (PGPSignatureList) obj;

		if (sigList.isEmpty()) {
			LOGGER.error("No signatures found in signature data");
			return false;
		}

		for (int i = 0; i < sigList.size(); i++) {
			PGPSignature sig = sigList.get(i);

			int sigType = sig.getSignatureType();
			if (sigType != PGPSignature.BINARY_DOCUMENT && sigType != PGPSignature.CANONICAL_TEXT_DOCUMENT) {
				continue;
			}

			PGPPublicKey key = keyRings.getPublicKey(sig.getKeyID());
			if (key == null) {
				continue;
			}

			sig.init(new BcPGPContentVerifierBuilderProvider(), key);
			sig.update(data);

			if (sig.verify()) {
				return true;
			}
		}

		LOGGER.error("No valid signature found matching provided public key");
		return false;
	}
}
