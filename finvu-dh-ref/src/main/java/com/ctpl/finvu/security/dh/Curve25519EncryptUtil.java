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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

public class Curve25519EncryptUtil {
	
	RandomString randSessionIdGen;
	
	public Curve25519EncryptUtil() {
		randSessionIdGen = new RandomString();
	}
	
	/**
	 * Generate a Diffie Hellman Key Pair.
	 * @return
	 */
	public KeyPair generateDHKeyPair() {
		Curve25519KeyPair keyPair = Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
		return Curve25519Wrapper.getKeyPair(keyPair);
	}
	
	/**
	 * Parse the encoded (Base64) pubKey and pvtKey and create a Key Pair.
	 * @param pubKey
	 * @param pvtKey
	 * @return
	 */
	public KeyPair parseKeyPair(String pubKey, String pvtKey) {
		byte[] pubKeyB = decode(pubKey);
		byte[] pvtKeyB = decode(pvtKey);
		return Curve25519Wrapper.getKeyPair(pubKeyB, pvtKeyB);
	}
	
	/**
	 * Get Base64 encoded public key from the keyPair.
	 * 
	 * @param keyPair
	 * @return
	 */
	public String getEncodedPubKey(KeyPair keyPair) {
		byte[] pubKeyEnc = keyPair.getPublic().getEncoded();
		return Base64.getEncoder().encodeToString(pubKeyEnc);
	}
	
	/**
	 * Get Base64 encoded private key from keyPair.
	 * 
	 * @param keyPair
	 * @return
	 */
	public String getEncodedPrivateKey(KeyPair keyPair) {
		byte[] pubKeyEnc = keyPair.getPrivate().getEncoded();
		return Base64.getEncoder().encodeToString(pubKeyEnc);		
	}
	
	/**
	 * Encrypt message using our KeyPair, remote Public key and remote session id.
	 * 
	 * @param message
	 * @param ourKeyPair
	 * @param encodedRemotePubKey
	 * @param sessionId
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public CryptoObject encrypt(byte[] message, KeyPair ourKeyPair, String encodedRemotePubKey, String remoteSessionId)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException,
			IllegalBlockSizeException, IOException {
		
		// decode the senders public key.
		byte[] remotePubKey = decode(encodedRemotePubKey);
		
		// calculate shared secret.
		Curve25519 curve25519 = Curve25519.getInstance(Curve25519.BEST);
		byte[] sharedSecret = curve25519.calculateAgreement(remotePubKey, ourKeyPair.getPrivate().getEncoded());
		
		byte[] localSessionId = randSessionIdGen.nextString().getBytes();
		
		SecretKeySpec aesKey = createKeySpec(sharedSecret, ourKeyPair, remotePubKey, remoteSessionId.getBytes(), localSessionId);
	    
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
        object.setLocalSessionId(localSessionId);
		
		return object;
	}
	
	/**
	 * Decrypt message set in the object.
	 * 
	 * @param object
	 * @param ourKeyPair
	 * @param encodedRemotePubKey
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	public byte[] decrypt(CryptoObject object, KeyPair ourKeyPair, String encodedRemotePubKey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, IOException {
		
		// decode the senders public key.
		byte[] remotePubKey = decode(encodedRemotePubKey);
		
		// calculate shared secret.
		Curve25519 curve25519 = Curve25519.getInstance(Curve25519.BEST);
		byte[] sharedSecret = curve25519.calculateAgreement(remotePubKey, ourKeyPair.getPrivate().getEncoded());
		
		SecretKeySpec aesKey = createKeySpec(sharedSecret, ourKeyPair, remotePubKey, object.getLocalSessionId(), object.getRemoteSessionId());
		
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
	
	private SecretKeySpec createKeySpec(byte[] sharedSecret, KeyPair ourKeyPair, byte[] remotePubKey, byte[] remoteSessionId, byte[] localSessionId) throws NoSuchAlgorithmException {
		 // Derive a key from the shared secret and both public keys
	    MessageDigest hash = MessageDigest.getInstance("SHA-256");
	    hash.update(sharedSecret);
	    // Simple deterministic ordering
		List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourKeyPair.getPublic().getEncoded()),
				ByteBuffer.wrap(remotePubKey));
	    Collections.sort(keys);
	    hash.update(keys.get(0));
	    hash.update(keys.get(1));
	    hash.update(remoteSessionId);
	    hash.update(localSessionId);

	    byte[] derivedKey = hash.digest();
	    
	    SecretKeySpec aesKey = new SecretKeySpec(derivedKey, 0, 16, "AES");
	    return aesKey;
	}
}
