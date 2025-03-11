package apo;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import javax.crypto.Cipher;

import org.bouncycastle.util.encoders.Hex;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
public class MainController
{
	@PostMapping("/verify")
	public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file,
			@RequestParam("sign") String sign) throws Exception
	{
		byte[] data = file.getBytes();
		boolean isValid = verifySignature(data, Base64.getDecoder().decode(sign), "data/priv.pem");
		return ResponseEntity.ok("Signature is " + (isValid ? "VALID" : "INVALID"));
	}

	@GetMapping("/generate")
	public ResponseEntity<byte[]> random() throws Exception
	{
		byte[] data = new byte[111];
		Random rnd = new Random();
		rnd.setSeed(100);
		rnd.nextBytes(data);
		data = Hex.encode(data);
		HttpHeaders headers = new HttpHeaders();
		headers.add(HttpHeaders.CONTENT_TYPE, "application/octet-stream");
		String sign = new String(Base64.getEncoder().encode(sign(data, "data/priv.pem")));
		headers.add("SIGN", sign);

		return new ResponseEntity<>(data, headers, HttpStatus.OK);
	}

	public static byte[] sha256(byte[] data) throws NoSuchAlgorithmException
	{
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(data);
	}

	public static boolean verifySignature(byte[] data, byte[] signatureBytes, String keyPath) throws Exception
	{
		String privateKeyPEM = new String(Files.readAllBytes(Paths.get(keyPath)));
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "").replaceAll("\\s+", "");

		byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedData = Hex.decode(cipher.doFinal(signatureBytes));

		byte[] expected = sha256(data);

		System.err.println(Hex.toHexString(signatureBytes));
		System.err.println(Hex.toHexString(decryptedData));
		System.err.println(Hex.toHexString(expected));

		return Arrays.equals(expected, decryptedData);
	}

	public static byte[] sign(byte[] data, String keyPath) throws Exception
	{
		String keyPEM = new String(Files.readAllBytes(Paths.get(keyPath)));
        String privateKeyPEM = keyPEM
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);

        return signature.sign();
    }
	
}
