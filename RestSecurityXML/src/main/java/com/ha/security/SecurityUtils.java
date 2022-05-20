package com.ha.security;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

import org.springframework.security.crypto.codec.Base64;

/**
 * This Class contains data Security related methods.
 */
public class SecurityUtils {

	/**
	 * This method Generates a String using HMAC-MD5 hashing algorithm
	 * 
	 * @param input
	 * @return secret
	 */
	public static String getAuthenticationTokenOrSecret(String input) {
		String secret = "";
		try {
			// Generate a key for the HMAC-MD5 keyed-hashing
			// algorithm; see RFC
			// 2104
			// In practice, you would save this key.
			KeyGenerator keyGen = KeyGenerator.getInstance("HmacMD5");
			SecretKey key = keyGen.generateKey();

			// Create a MAC object using HMAC-MD5 and initialize
			// with key
			Mac mac = Mac.getInstance(key.getAlgorithm());
			mac.init(key);

			// Encode the string into bytes using utf-8 and digest
			// it
			byte[] utf8 = input.getBytes("UTF8");
			byte[] digest = mac.doFinal(utf8);

			// If desired, convert the digest into a string
			// secret = new sun.misc.BASE64Encoder().encode(digest);

			secret = new String(Base64.encode(digest));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return secret;
	}

}
