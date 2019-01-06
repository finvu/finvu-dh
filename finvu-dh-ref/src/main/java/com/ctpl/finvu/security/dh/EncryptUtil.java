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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * @author praveenp
 *
 */
public interface EncryptUtil {

	/**
	 * Generate a DH key pair.
	 * 
	 * @return
	 */
	KeyPair generateDHKeyPair();
	
	/**
	 * Parse an base64 encoded public and private key.
	 * 
	 * @param pubKey
	 * @param pvtKey
	 * @return
	 */
	KeyPair parseKeyPair(String pubKey, String pvtKey);
	
	/**
	 * Get base 64 encoded public key.
	 * 
	 * @param keyPair
	 * @return
	 */
	default String getEncodedPubKey(KeyPair keyPair) {
		byte[] pubKeyEnc = keyPair.getPublic().getEncoded();
		return Base64.getEncoder().encodeToString(pubKeyEnc);
	}
	
	/**
	 * Get base 64 encoded private key. This key should never
	 * be sent on the network.
	 * 
	 * @param keyPair
	 * @return
	 */
	default String getEncodedPrivateKey(KeyPair keyPair) {
		byte[] pubKeyEnc = keyPair.getPrivate().getEncoded();
		return Base64.getEncoder().encodeToString(pubKeyEnc);		
	}
	
	/**
	 * Encrypt a message. This method will use the DH parameter
	 * from the encodedRemotePubKey and will create a shared
	 * secret and a key to encrypt the message and then encode
	 * the message using base64 encoding. 
	 * 
	 * @param message
	 * @param myKeyPair
	 * @param encodedRemotePubKey
	 * @param remoteNonce
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	CryptoObject encrypt(byte[] message, KeyPair myKeyPair, String encodedRemotePubKey, String remoteNonce) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException;
	
	/**
	 * Decrypt a message. The public key of the remote user must be passed and assumed
	 * to be base64 encoded.
	 * 
	 * @param object
	 * @param ourKeyPair
	 * @param encodedRemotePubKey
	 * @param localNonce
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	byte[] decrypt(CryptoObject object, KeyPair ourKeyPair, String encodedRemotePubKey, String localNonce)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException;
	
}