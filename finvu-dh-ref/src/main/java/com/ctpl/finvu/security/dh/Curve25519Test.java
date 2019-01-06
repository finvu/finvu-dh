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

import java.security.KeyPair;
import java.util.Base64;
import java.util.UUID;

/**
 * @author praveenp
 *
 */
public class Curve25519Test {

	public static void main(String[] args) throws Exception {
	
		// Alice is initiator and decrypter and Bob is encrypter
	
		// ######## Alice's domain start ##############
		
		Curve25519EncryptUtil aliceUtil = new Curve25519EncryptUtil();
		
		// Alice generates a DH Key pair and a UUID
		KeyPair aliceKeyPair  = aliceUtil.generateDHKeyPair();
		String encodedAlicePubKey = aliceUtil.getEncodedPubKey(aliceKeyPair);
		String encodedAlicePvtKey = aliceUtil.getEncodedPrivateKey(aliceKeyPair);
	
		UUID aliceUUID = UUID.randomUUID();
		
		System.out.println("#### Alice's domain ###");
		System.out.println("Alice PubKey (to send to Bob): [" + encodedAlicePubKey + "]");
		System.out.println("Alice Nonce: (to send to Bob): [" + aliceUUID + "]");
		System.out.println();

		// Alice sends DH public key and nonce to Bob's domain
		
		// ######## Alice's domain end ##############

		
		// ######## Bob's domain start ##############

		Curve25519EncryptUtil bobUtil = new Curve25519EncryptUtil();		

		// Bob generates his DH Key pair.
		KeyPair bobKeyPair = bobUtil.generateDHKeyPair();
		String encodedBobPubKey = bobUtil.getEncodedPubKey(bobKeyPair);
		
		String dataToEncrypt = "Hello World!";
		System.out.println("#### Bob's domain ###");
		System.out.println("Data to Encrypt: [" + dataToEncrypt + "]");
		
		// Bob calculates shared secret using his private key and alice public key
		// and encrypts data by geneating a 256 BIT AES session key which is
		// computed using Shared secret, Alice's nonce and Bob's nonce
		// which is generated as part of the encryption process.
		CryptoObject object = bobUtil.encrypt(dataToEncrypt.getBytes(), bobKeyPair, encodedAlicePubKey, aliceUUID.toString());
		
		System.out.println("Bob PubKey: (to send to Alice): [" + encodedBobPubKey + "]");
		System.out.println("Bob Nonce: (to send to Alice): [" + object.getNonce() + "]");
		System.out.println("Bob AES parameters (to send to Alice): [" + new String(Base64.getEncoder().encode(object.getParameter())) + "]");
		System.out.println();
		
		// Bob sends encrypted message, AES parameters used to generate the session key
		// and Bob's nonce to Alice.
		
		// ######## Bob's domain end ##############
		
		
		// ######## Alice's domain start ##############
		System.out.println("#### Alice's domain ###");
		String encodedEncryptedMsg = new String(Base64.getEncoder().encode(object.getEncryptedData()));
		String encodedAesParams = new String(Base64.getEncoder().encode(object.getParameter()));
		String bobUUID = object.getNonce();
		
		object = new CryptoObject();
		object.setEncryptedData(Base64.getDecoder().decode(encodedEncryptedMsg));
		object.setParameter(Base64.getDecoder().decode(encodedAesParams));
		object.setNonce(bobUUID);
		
		aliceKeyPair = aliceUtil.parseKeyPair(encodedAlicePubKey, encodedAlicePvtKey);

		// Alice uses her private key and bob's public key to calculate the shared secret.  
		// Alice uses shared secret, her nonce and bob's nonce and AES parameter received
		// from Bob to generate 256 bit session key.
		// Alice then decrypts the data using the session key.
		String decryptedData = new String(aliceUtil.decrypt(object, aliceKeyPair, encodedBobPubKey, aliceUUID.toString()));
		System.out.println("Decrypted data: [" + decryptedData + "]");
		
		// ######## Alice's domain end ##############
	}

}
