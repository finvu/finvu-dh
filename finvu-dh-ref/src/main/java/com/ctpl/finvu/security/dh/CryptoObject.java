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

/**
 * @author praveenp
 *
 */
public class CryptoObject {

	private byte[] parameter; //AES Parameter
	private byte[] encryptedData;
	private String nonce; // UUID as string.
	
	/**
	 * @return the parameter
	 */
	public byte[] getParameter() {
		return parameter;
	}
	
	/**
	 * @param parameter the parameter to set
	 */
	public void setParameter(byte[] parameter) {
		this.parameter = parameter;
	}
	
	/**
	 * @return the encryptedData
	 */
	public byte[] getEncryptedData() {
		return encryptedData;
	}
	
	/**
	 * @param encryptedData the encryptedData to set
	 */
	public void setEncryptedData(byte[] encryptedData) {
		this.encryptedData = encryptedData;
	}

	/**
	 * @return the nonce
	 */
	public String getNonce() {
		return nonce;
	}

	/**
	 * @param nonce the nonce to set
	 */
	public void setNonce(String nonce) {
		this.nonce = nonce;
	}
	
}
