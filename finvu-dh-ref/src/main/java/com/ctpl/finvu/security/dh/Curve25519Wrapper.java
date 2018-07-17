package com.ctpl.finvu.security.dh;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.whispersystems.curve25519.Curve25519KeyPair;

public class Curve25519Wrapper {

	public static KeyPair getKeyPair(final Curve25519KeyPair keyPair) {
		return getKeyPair(keyPair.getPublicKey(), keyPair.getPrivateKey());
	}
	
	public static KeyPair getKeyPair(final byte[] pubKey, final byte[] pvtKey) {
		
		PublicKey publicKey = new PublicKey() {
			
			private static final long serialVersionUID = 6080337888151230758L;
			
			public String getFormat() {
				return null;
			}
			
			public byte[] getEncoded() {
				return pubKey;
			}
			
			public String getAlgorithm() {
				return null;
			}
		};
		
		PrivateKey privateKey = new PrivateKey() {
			
			private static final long serialVersionUID = -1026627412270374446L;
			
			public String getFormat() {
				return null;
			}
			
			public byte[] getEncoded() {
				return pvtKey;
			}
			
			public String getAlgorithm() {
				return null;
			}
		};
		
		return new KeyPair(publicKey, privateKey);
	}
}
