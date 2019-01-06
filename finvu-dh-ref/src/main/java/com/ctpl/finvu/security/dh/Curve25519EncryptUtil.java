/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ctpl.finvu.security.dh;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

/**
 * @author praveenp
 *
 */
public class Curve25519EncryptUtil implements EncryptUtil {

	/* (non-Javadoc)
	 * @see com.ctpl.finvu.common.security.auth.dh.EncryptUtil#generateDHKeyPair()
	 */
	@Override
	public KeyPair generateDHKeyPair() {
		Curve25519KeyPair keyPair = Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
		return Curve25519Wrapper.getKeyPair(keyPair);
	}

	/* (non-Javadoc)
	 * @see com.ctpl.finvu.common.security.auth.dh.EncryptUtil#parseKeyPair(java.lang.String, java.lang.String)
	 */
	@Override
	public KeyPair parseKeyPair(String pubKey, String pvtKey) {
		byte[] pubKeyB = decode(pubKey);
		byte[] pvtKeyB = decode(pvtKey);
		return Curve25519Wrapper.getKeyPair(pubKeyB, pvtKeyB);
	}

	/* (non-Javadoc)
	 * @see com.ctpl.finvu.common.security.auth.dh.EncryptUtil#encrypt(byte[], java.lang.String)
	 */
	@Override
	public CryptoObject encrypt(byte[] message, KeyPair ourKeyPair, String encodedRemotePubKey, String remoteNonce)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, IOException {
		
		// decode the senders public key.
		byte[] remotePubKey = decode(encodedRemotePubKey);
		
		// calculate shared secret.
		Curve25519 curve25519 = Curve25519.getInstance(Curve25519.BEST);
		byte[] sharedSecret = curve25519.calculateAgreement(remotePubKey, ourKeyPair.getPrivate().getEncoded());
		
		String localNonce = UUID.randomUUID().toString();
		SecretKeySpec aesKey = createKeySpec(sharedSecret, localNonce, remoteNonce);
	    
		/*
		 * encrypt using AES in CBC mode
		 */
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, aesKey);
		byte[] ciphertext = cipher.doFinal(message);

		// Retrieve the parameter that was used. It needs to be transfered to
		// remote party in encoded format
		byte[] encodedParams = cipher.getParameters().getEncoded();

		CryptoObject object = new CryptoObject();
        
		object.setEncryptedData(ciphertext);
		object.setParameter(encodedParams);
		object.setNonce(localNonce.toString());
		
		return object;
	}

	/* (non-Javadoc)
	 * @see com.ctpl.finvu.common.security.auth.dh.EncryptUtil#decrypt(java.lang.String, java.lang.String)
	 */
	@Override
	public byte[] decrypt(CryptoObject object, KeyPair ourKeyPair, String encodedRemotePubKey, String localNonce)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException {
		
		// decode the senders public key.
		byte[] remotePubKey = decode(encodedRemotePubKey);
		
		// calculate shared secret.
		Curve25519 curve25519 = Curve25519.getInstance(Curve25519.BEST);
		byte[] sharedSecret = curve25519.calculateAgreement(remotePubKey, ourKeyPair.getPrivate().getEncoded());
		SecretKeySpec aesKey = createKeySpec(sharedSecret, localNonce, object.getNonce());
		
		/*
		 * decrypt using AES in CBC mode
		 */
		AlgorithmParameters aesParams = AlgorithmParameters.getInstance("AES");
		aesParams.init(object.getParameter());

		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, aesKey, aesParams);
		return cipher.doFinal(object.getEncryptedData());
	}
	
	private byte[] decode(String value) {
		return Base64.getDecoder().decode(value);
	}
	
	private SecretKeySpec createKeySpec(byte[] sharedSecret, String localNonce,
			String remoteNonce) throws NoSuchAlgorithmException {
		 // Derive a key from the shared secret and both public keys
	    MessageDigest hash = MessageDigest.getInstance("SHA-256");
	    hash.update(sharedSecret);
	    // Simple deterministic ordering, to ensure same order of nonce is used
	    // when calculating the key for both encrypt and decrypt.	   
		List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(localNonce.getBytes()),
				ByteBuffer.wrap(remoteNonce.getBytes()));
	    Collections.sort(keys);
	    hash.update(keys.get(0));
	    hash.update(keys.get(1));

	    byte[] derivedKey = hash.digest();
	    
	    SecretKeySpec aesKey = new SecretKeySpec(derivedKey, 0, 32, "AES");
	    return aesKey;
	}
}
