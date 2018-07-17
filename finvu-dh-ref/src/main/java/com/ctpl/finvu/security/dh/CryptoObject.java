package com.ctpl.finvu.security.dh;

public class CryptoObject {

	private byte[] parameter;
	private byte[] encryptedData;
	private byte[] remoteSessionId;
	private byte[] localSessionId;
	
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
	 * @return the remoteSessionId
	 */
	public byte[] getRemoteSessionId() {
		return remoteSessionId;
	}

	/**
	 * @param remoteSessionId the remoteSessionId to set
	 */
	public void setRemoteSessionId(byte[] remoteSessionId) {
		this.remoteSessionId = remoteSessionId;
	}

	/**
	 * @return the localSessionId
	 */
	public byte[] getLocalSessionId() {
		return localSessionId;
	}

	/**
	 * @param localSessionId the localSessionId to set
	 */
	public void setLocalSessionId(byte[] localSessionId) {
		this.localSessionId = localSessionId;
	}
	
}
