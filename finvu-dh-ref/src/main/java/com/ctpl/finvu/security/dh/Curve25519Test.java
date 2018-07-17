package com.ctpl.finvu.security.dh;

import java.security.KeyPair;
import java.util.Base64;

public class Curve25519Test {

	public static void main(String[] args) throws Exception {
		
		String fiData = "This is FI Data";
		
		// Utility used by FIU for key generation and decryption.
		Curve25519EncryptUtil fiuUtil = new Curve25519EncryptUtil();
		
		// Utility used by FIP for key generation and encryption.
		Curve25519EncryptUtil fipUtil = new Curve25519EncryptUtil();
		
		// FIU Generates a key pair, encodes and stores it for later use. Sends public key to FIP.
		KeyPair fiuKeyPair  = fiuUtil.generateDHKeyPair();
		String encodedFiuPubKey = fiuUtil.getEncodedPubKey(fiuKeyPair);
		String encodedFiuPvtKey = fiuUtil.getEncodedPrivateKey(fiuKeyPair);
		
		// FIU Generates a 32 byte random value and sends it to FIP.
		RandomString randSessionIdGen = new RandomString();
		String sessionId = randSessionIdGen.nextString();
		
		// FIP receives FIU public key and 32 byte random value from FIU.
		// FIP Generates a key pair and encodes public key for encryption.
		KeyPair fipKeyPair = fipUtil.generateDHKeyPair();
		String encodedFipPubKey = fipUtil.getEncodedPubKey(fipKeyPair);
		
		// FIP encrypts the FI data using FIU public key and random value.
		// FIP also generates 32 byte random value
		CryptoObject object = fipUtil.encrypt(fiData.getBytes(), fipKeyPair, encodedFiuPubKey, sessionId);
		
		// FIP encodes and sends encrypted message, FIP public key, encoded AES parameters, and FIP random value to FIU
		String encodedEncryptedMsg = new String(Base64.getEncoder().encode(object.getEncryptedData()));
		String encodedAesParams = new String(Base64.getEncoder().encode(object.getParameter()));
		
		// FIU uses FIP supplied values and decrypts the  message.
		byte[] remoteSessionId = object.getLocalSessionId();
		object = new CryptoObject();
		object.setEncryptedData(Base64.getDecoder().decode(encodedEncryptedMsg));
		object.setParameter(Base64.getDecoder().decode(encodedAesParams));
		object.setRemoteSessionId(remoteSessionId);
		object.setLocalSessionId(sessionId.getBytes());
		
		fiuKeyPair = fiuUtil.parseKeyPair(encodedFiuPubKey, encodedFiuPvtKey);
		System.out.println(new String(fiuUtil.decrypt(object, fiuKeyPair, encodedFipPubKey)));

	}

}
