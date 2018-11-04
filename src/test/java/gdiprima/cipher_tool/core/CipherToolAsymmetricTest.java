package gdiprima.cipher_tool.core;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import gdiprima.cipher_tool.utils.FileManager;

public class CipherToolAsymmetricTest {
	private static String text;
	private static String iv;
	private static byte[] testFile;

	@BeforeClass
	public static void initVariables() throws IOException {
		text = "Hello World!!!";
		iv = UUID.randomUUID().toString();
		testFile = FileManager.readFileContent("file://" + CipherToolAsymmetricTest.class.getClassLoader().getResource("./test-file").getPath());
	}
	
	@Before
	public void before() {
		System.out.println("----------------------------------");
	}
	
	@After
	public void after() {
		System.out.println("----------------------------------");
	}

	@Test
	public void rsaEcbPkcs1_1024Text() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_PKCS1_1024, text.getBytes());
	}
	
	@Test
	public void rsaEcbPkcs1_2048Text() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_PKCS1_2048, text.getBytes());
	}

	@Test
	public void rsaEcbOaepSha1_1024Text() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA1_1024, text.getBytes());
	}
	
	@Test
	public void rsaEcbOaepSha1_2048Text() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA1_2048, text.getBytes());
	}

	@Test
	public void rsaEcbOaepSha2_1024Text() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA2_1024, text.getBytes());
	}
	
	@Test
	public void rsaEcbOaepSha2_2048Text() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA2_2048, text.getBytes());
	}

	@Test
	public void rsaEcbPkcs1_1024File() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_PKCS1_1024, testFile);
	}
	
	@Test
	public void rsaEcbPkcs1_2048File() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_PKCS1_2048, testFile);
	}

	@Test
	public void rsaEcbOaepSha1_1024File() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA1_1024, testFile);
	}
	
	@Test
	public void rsaEcbOaepSha1_2048File() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA1_2048, testFile);
	}

	@Test
	public void rsaEcbOaepSha2_1024File() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA2_1024, testFile);
	}
	
	@Test
	public void rsaEcbOaepSha2_2048File() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		asymmetricCipherTest(SupportedCipherTransformations.RSA_ECB_OAEP_SHA2_2048, testFile);
	}
	
	private String asymmetricCipherTest(SupportedCipherTransformations type, byte[] src) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		System.out.println("Encryption Algorithm: " + type.name());
		KeyPair keyPair = CipherTool.readKeyFromPemFile(
				"file://" + this.getClass().getClassLoader().getResource(String.format("./public_%d.pem", type.getKeyLenght())).getPath(), 
				"file://" + this.getClass().getClassLoader().getResource(String.format("./private_%d_key.pem", type.getKeyLenght())).getPath()
		);
		CipherTool tool = new CipherTool().initAsymmetricTransformation(iv, keyPair.getPublic(), keyPair.getPrivate(), type);
		String ecr = tool.encrypt(src);
		System.out.println("\tEncrypted value: " + (ecr.length() > 100 ? (ecr.substring(0, 100) + "...") : ecr));
		byte[] dcr = tool.decrypt(ecr);
		String dec = new String(dcr);
		System.out.println("\tDecrypted value: " + (dec.length() > 100 ? (dec.substring(0, 100) + "...") : dec));
		Assert.assertArrayEquals(src, dcr);
		return ecr;
	}
	
}
