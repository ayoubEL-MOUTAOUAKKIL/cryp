package crypto;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Encrypter {

	private static final SecureRandom RAND = new SecureRandom();
	private byte[] iv;

	
	public Encrypter() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Security.addProvider(new BouncyCastleProvider());
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
		int ivSize = cipher.getBlockSize();
		iv = new byte[ivSize];
		for(int i = 0 ; i< ivSize;i++) {
			iv[i]='a';
		}
	}
	
	public SecretKey keyGenerator(String s) throws NoSuchAlgorithmException, InvalidKeySpecException{
		byte[] salt = new String("12345678").getBytes();
		int iterationCount = 1024;
		KeySpec keySpec = new PBEKeySpec(s.toCharArray(), salt, iterationCount, 128);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();
		SecretKey key = new SecretKeySpec(keyBytes, "AES");
		return key;
	}
	public String encrypt(String question, String previousResponse) throws IOException {
		Security.addProvider(new BouncyCastleProvider());
		try {
			Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			SecretKey key = keyGenerator(previousResponse);
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

			byte[] encryptedQuestion = cipher.doFinal(question.getBytes());

			return new String(encryptedQuestion);

		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public String decrypt(String question , String previousResponse) throws GeneralSecurityException, UnsupportedEncodingException {
        Security.addProvider(new BouncyCastleProvider());
        
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        
        SecretKey key = keyGenerator(previousResponse);
        
        cipher.init(Cipher.DECRYPT_MODE,key,new IvParameterSpec(iv));
        byte[] decryptedAnswer = cipher.doFinal(question.getBytes());
        
        return new String(decryptedAnswer);
        
    }

    
	
	

	public static void main(String[] args) throws IOException, GeneralSecurityException {

		Encrypter e = new Encrypter();
		Encrypter e2 = new Encrypter();
		String s = e.encrypt("ok","ok");
		String v = e.decrypt(s, "ok");
		System.out.println(s + "---" +v);
		
		

	}

}
