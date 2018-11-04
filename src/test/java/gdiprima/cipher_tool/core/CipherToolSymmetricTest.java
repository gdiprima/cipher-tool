package gdiprima.cipher_tool.core;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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

public class CipherToolSymmetricTest {
	private static String text;
	private static String iv;
	private static String salt;
	private static String password;
	private static byte[] testFile;
	
	@BeforeClass
	public static void initVariables() throws IOException {
		text = "Hello World!!!";
		iv = UUID.randomUUID().toString();
		salt = UUID.randomUUID().toString();
		password = "thisIsMyS3cr3tP4ssw0rd";
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
	public void aesCbcNoPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_CBC_NOPAD, text.getBytes());
	}
	
	@Test
	public void aesCbcPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_CBC_PKCS5, text.getBytes());
	}
	
	@Test
	public void aesEcbNoPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_ECB_NOPAD, text.getBytes());
	}
	
	@Test
	public void aesEcbPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_ECB_PKCS5, text.getBytes());
	}
	
	@Test
	public void desCbcNoPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_CBC_NOPAD, text.getBytes());
	}
	
	@Test
	public void desCbcPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_CBC_PKCS5, text.getBytes());
	}
	
	@Test
	public void desEcbNoPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_ECB_NOPAD, text.getBytes());
	}
	
	@Test
	public void desEcbPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_ECB_PKCS5, text.getBytes());
	}
	
	@Test
	public void des3CbcNoPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_CBC_NOPAD, text.getBytes());
	}
	
	@Test
	public void des3CbcPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_CBC_PKCS5, text.getBytes());
	}
	
	@Test
	public void des3EcbNoPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_ECB_NOPAD, text.getBytes());
	}
	
	@Test
	public void des3EcbPadText() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_ECB_PKCS5, text.getBytes());
	}
	
	@Test
	public void aesCbcNoPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_CBC_NOPAD, testFile);
	}
	
	@Test
	public void aesCbcPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_CBC_PKCS5, testFile);
	}
	
	@Test
	public void aesEcbNoPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_ECB_NOPAD, testFile);
	}
	
	@Test
	public void aesEcbPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.AES_ECB_PKCS5, testFile);
	}
	
	@Test
	public void desCbcNoPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_CBC_NOPAD, testFile);
	}
	
	@Test
	public void desCbcPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_CBC_PKCS5, testFile);
	}
	
	@Test
	public void desEcbNoPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_ECB_NOPAD, testFile);
	}
	
	@Test
	public void desEcbPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES_ECB_PKCS5, testFile);
	}
	
	@Test
	public void des3CbcNoPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_CBC_NOPAD, testFile);
	}
	
	@Test
	public void des3CbcPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_CBC_PKCS5, testFile);
	}
	
	@Test
	public void des3EcbNoPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_ECB_NOPAD, testFile);
	}
	
	@Test
	public void des3EcbPadFile() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		symmetricCipherTest(SupportedCipherTransformations.DES3_ECB_PKCS5, testFile);
	}
	
	private void symmetricCipherTest(SupportedCipherTransformations type, byte[] src) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		System.out.println("Encryption Algorithm: " + type.name());
		CipherTool tool = new CipherTool().initSymmetricTransformation(iv, salt, password, type);
		String ecr = tool.encrypt(src);
		System.out.println("\tEncrypted value: " + (ecr.length() > 100 ? (ecr.substring(0, 100) + "...") : ecr));
		byte[] dcr = tool.decrypt(ecr);
		String dec = new String(dcr);
		System.out.println("\tDecrypted value: " + (dec.length() > 100 ? (dec.substring(0, 100) + "...") : dec));
		Assert.assertArrayEquals(src, dcr);
	}
}
