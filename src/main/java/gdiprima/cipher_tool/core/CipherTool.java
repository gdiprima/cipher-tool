package gdiprima.cipher_tool.core;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import gdiprima.cipher_tool.utils.FileManager;

public class CipherTool {
	private static byte FILLER = 0x0;
	private int fillerLength;
	private String initVector;
	private String key;
	private String salt;
	private SecretKey sKey;
	private PublicKey publicKey;
	private PrivateKey privateKey;
	private IvParameterSpec iv;
	private SecretKeySpec skeySpec;
	private Cipher cipher;
	private SupportedCipherTransformations type;

	public CipherTool() {
		// Empty Constructor
	}
	
	public static KeyPair generateRSAKeyPair(int keyLength) throws NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	    keyPairGenerator.initialize(keyLength);
	    KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}
	
	public static KeyPair readKeyFromPemFile(String pubPem, String privPem) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		PrivateKey privateKey = readPrivateKeyFromPemFile(privPem);
	    PublicKey publicKey = readPublicKeyFromPemFile(pubPem);
		KeyPair keyPair = new KeyPair(publicKey, privateKey);
		return keyPair;
	}
	
	public static PublicKey readPublicKeyFromPemFile(String pubPem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String pubFileContent = FileManager.readFileAsString(pubPem);
		pubFileContent = pubFileContent.replaceAll("-----(BEGIN|END)( RSA)? PUBLIC KEY-----\\s?", "");
		byte[] pubKey = Base64.getDecoder().decode(pubFileContent);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpecPub = new X509EncodedKeySpec(pubKey);
	    PublicKey publicKey = kf.generatePublic(keySpecPub);
	    return publicKey;
	}
	
	public static PrivateKey readPrivateKeyFromPemFile(String privPem) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		String privFileContent = FileManager.readFileAsString(privPem);
		privFileContent = privFileContent.replaceAll("-----(BEGIN|END)( RSA)? PRIVATE KEY-----\\s?", "");
		byte[] privKey = Base64.getDecoder().decode(privFileContent);
		KeyFactory kf = KeyFactory.getInstance("RSA");
	    PKCS8EncodedKeySpec keySpecPriv = new PKCS8EncodedKeySpec(privKey);
	    PrivateKey privateKey = kf.generatePrivate(keySpecPriv);
	    return privateKey;
	}
	
	public CipherTool initSymmetricTransformation(String iv, String key, SupportedCipherTransformations type) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
		this.initVector = iv;
		this.key = key;
		this.type = type;
		prepareCipher();
		return this;
	}
	
	public CipherTool initSymmetricTransformation(String iv, String salt, String password, SupportedCipherTransformations type) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException {
		this.initVector = iv;
		this.salt = salt;
		this.type = type;
		this.sKey = getKeyFromPassword(password);
		prepareCipher();
		return this;
	}
	
	public CipherTool initAsymmetricTransformation(String initVector, PublicKey pub, PrivateKey priv, SupportedCipherTransformations type) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
		this.initVector = initVector;
		this.publicKey = pub;
		this.privateKey = priv;
		this.type = type;
		prepareCipher();
		return this;
	}

	public String encrypt(byte[] value) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		byte[] encrypted = encryptRaw(value);
		return Base64.getEncoder().encodeToString(encrypted);
	}

	public byte[] decrypt(String value) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] enc = Base64.getDecoder().decode(value);
		return decryptRaw(enc);
	}
	
	private byte[] encryptRaw(byte[] value) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		if (!type.isRSA()) {
			if (type.isNoIv()) {
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			} else {
				cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			}
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		}
		if (type.isNoPad()) {
			fillerLength = 0;
			while((value.length % (type.getKeyLenght()/8)) != 0) {
				value = append(value, FILLER);
				fillerLength++;
			}
		}
		byte[] encrypted = new byte[0];
		int blockSize = type.getMaxBlockSize();
		if (type.isRSA() && value.length > blockSize) {
			for(int offset=0; offset < value.length; offset+=blockSize) {
				encrypted = concat(encrypted, encryptRaw(Arrays.copyOfRange(value, offset, Math.min(offset+blockSize, value.length))));
			}
		} else {
			encrypted = cipher.doFinal(value);
		}
		return encrypted;
	}
	
	private byte[] decryptRaw(byte[] enc) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] original = new byte[0];
		if (!type.isRSA()) {
			if (type.isNoIv()) {
				cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			} else {
				cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			}
			original = cipher.doFinal(enc);
		} else {
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			int blockSize = type.getKeyLenght()/8;
			if (enc.length > blockSize) {
				for(int offset=0; offset < enc.length; offset+=blockSize) {
					original = concat(original, decryptRaw(Arrays.copyOfRange(enc, offset, Math.min(offset+blockSize, enc.length))));
				}
			} else {
				original = cipher.doFinal(enc);
			}
		}
		
		if (type.isNoPad() && fillerLength != 0) {
			original = Arrays.copyOf(original, original.length - fillerLength);
		}
		return original;
	}

	private SecretKey getKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 10000, type.getKeyLenght());
		return factory.generateSecret(spec);
	}

	private void prepareCipher() throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
		if (!type.isNoIv()) {
			iv = new IvParameterSpec(createInitialVector());
		}
		if (!type.isRSA()) {
			skeySpec = new SecretKeySpec(sKey == null ? key.getBytes("UTF-8") : sKey.getEncoded(), type.getKeyName());
		}
		cipher = Cipher.getInstance(type.getCipherName());
	}

	private byte[] createInitialVector() throws UnsupportedEncodingException {
		int ivSize = type.getIvLenght();
		byte[] _ivS = initVector.getBytes("UTF-8");
		return Arrays.copyOf(_ivS, ivSize);
	}
	
	private static byte[] append(byte[] a, byte b) {
	    final int N = a.length;
	    a = Arrays.copyOf(a, N + 1);
	    a[N] = b;
	    return a;
	}
	
	private static byte[] concat(byte[] a, byte[] b) {
		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}

}
