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
import java.security.PrivateKey;
import java.security.PublicKey;

import org.whispersystems.curve25519.Curve25519KeyPair;

/**
 * @author praveenp
 *
 */
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
