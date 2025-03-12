package apo;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

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
//		data[2] = 2;
		boolean isValid = verifySignature(data, Base64.getDecoder().decode(sign), "data/pub.pem");
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
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
				.replace("-----END PUBLIC KEY-----", "").replaceAll("\\s+", "");

		byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
		PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        System.err.println(signature.getClass());
        signature.initVerify(publicKey);
        signature.update(data);

        return signature.verify(signatureBytes);
        
//		Cipher cipher = Cipher.getInstance("RSA");
//		cipher.init(Cipher.DECRYPT_MODE, privateKey);
//		byte[] decryptedData = Hex.decode(cipher.doFinal(signatureBytes));
//
//		byte[] expected = sha256(data);
//
//		System.err.println(Hex.toHexString(signatureBytes));
//		System.err.println(Hex.toHexString(decryptedData));
//		System.err.println(Hex.toHexString(expected));
//
//		return Arrays.equals(expected, decryptedData);
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
