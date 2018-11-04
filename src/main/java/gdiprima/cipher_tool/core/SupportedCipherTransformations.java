package gdiprima.cipher_tool.core;

public enum SupportedCipherTransformations {
	AES_CBC_NOPAD("AES/CBC/NoPadding", "AES", 128, true, false),
	AES_CBC_PKCS5("AES/CBC/PKCS5Padding", "AES", 128, false, false),
	AES_ECB_NOPAD("AES/ECB/NoPadding", "AES", 128, true, true),
	AES_ECB_PKCS5("AES/ECB/PKCS5Padding", "AES", 128, false, true),
	DES_CBC_NOPAD("DES/CBC/NoPadding", "DES", 64, true, false),
	DES_CBC_PKCS5("DES/CBC/PKCS5Padding", "DES", 64, false, false),
	DES_ECB_NOPAD("DES/ECB/NoPadding", "DES", 64, true, true),
	DES_ECB_PKCS5("DES/ECB/PKCS5Padding", "DES", 64, false, true),
	DES3_CBC_NOPAD("DESede/CBC/NoPadding", "DESede", 192, 8, true, false),
	DES3_CBC_PKCS5("DESede/CBC/PKCS5Padding", "DESede", 192, 8, false, false),
	DES3_ECB_NOPAD("DESede/ECB/NoPadding", "DESede", 192, true, true),
	DES3_ECB_PKCS5("DESede/ECB/PKCS5Padding", "DESede", 192, false, true),
	RSA_ECB_PKCS1_1024("RSA/ECB/PKCS1Padding", "RSA", 1024, 117),
	RSA_ECB_PKCS1_2048("RSA/ECB/PKCS1Padding", "RSA", 2048, 245),
	RSA_ECB_OAEP_SHA1_1024("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RSA", 1024, 86),
	RSA_ECB_OAEP_SHA1_2048("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RSA", 2048, 214),
	RSA_ECB_OAEP_SHA2_1024("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA", 1024, 62), 
	RSA_ECB_OAEP_SHA2_2048("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA", 2048, 190);
	
	private String cipherName;
	private String keyName;
	private int keyLength;
	private int ivLength;
	private int maxBlockSize;
	private boolean noPad;
	private boolean noIv;
	
	private SupportedCipherTransformations(String cipherName, String keyName, int keyLength, int maxBlockSize) {
		this(cipherName, keyName, keyLength, false, true);
		this.maxBlockSize = maxBlockSize;
	}
	
	private SupportedCipherTransformations(String cipherName, String keyName, int keyLength, boolean noPad, boolean noIv) {
		this.cipherName = cipherName;
		this.keyName = keyName;
		this.keyLength = keyLength;
		this.noPad = noPad;
		this.noIv = noIv;
		this.ivLength = this.keyLength/8;
	}
	
	private SupportedCipherTransformations(String cipherName, String keyName, int keyLength, int ivLength, boolean noPad, boolean noIv) {
		this(cipherName, keyName, keyLength, noPad, noIv);
		this.ivLength = ivLength;
	}
	
	public String getCipherName() {
		return this.cipherName;
	}
	
	public String getKeyName() {
		return this.keyName;
	}
	
	public boolean isRSA() {
		return "RSA".equals(this.keyName);
	}
	
	public int getKeyLenght() {
		return this.keyLength;
	}
	
	public int getIvLenght() {
		return this.ivLength;
	}
	
	public int getMaxBlockSize() {
		return this.maxBlockSize;
	}
	
	public boolean isNoPad() {
		return this.noPad;
	}
	
	public boolean isNoIv() {
		return noIv;
	}
}
