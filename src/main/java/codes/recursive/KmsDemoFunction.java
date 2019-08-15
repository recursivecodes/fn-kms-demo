package codes.recursive;

import com.oracle.bmc.auth.AbstractAuthenticationDetailsProvider;
import com.oracle.bmc.auth.ConfigFileAuthenticationDetailsProvider;
import com.oracle.bmc.auth.ResourcePrincipalAuthenticationDetailsProvider;
import com.oracle.bmc.keymanagement.KmsCryptoClient;
import com.oracle.bmc.keymanagement.model.DecryptDataDetails;
import com.oracle.bmc.keymanagement.requests.DecryptRequest;
import com.oracle.bmc.keymanagement.responses.DecryptResponse;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

public class KmsDemoFunction {

    private final String initVector;

    public KmsDemoFunction() {
        this.initVector = System.getenv().get("INIT_VECTOR_STRING");
    }

    public Map<String, String> decryptSensitiveValue() throws IOException {
        Boolean useResourcePrincipal = Boolean.valueOf(System.getenv().getOrDefault("USE_RESOURCE_PRINCIPAL", "true"));
        String encryptedPassword = System.getenv().get("ENCRYPTED_PASSWORD");
        String cipherTextDEK = System.getenv().get("DEK_CIPHERTEXT");
        String endpoint = System.getenv().get("ENDPOINT");
        String keyOcid = System.getenv().get("KEY_OCID");

        /*
        * when deployed, we can use a ResourcePrincipalAuthenticationDetailsProvider
        * for our the auth provider.
        * locally, we'll use a ConfigFileAuthenticationDetailsProvider
        */
        AbstractAuthenticationDetailsProvider provider = null;
        if( useResourcePrincipal ) {
            provider = ResourcePrincipalAuthenticationDetailsProvider.builder().build();
        }
        else {
            provider = new ConfigFileAuthenticationDetailsProvider("/.oci/config", "DEFAULT");
        }

        KmsCryptoClient cryptoClient = KmsCryptoClient.builder().endpoint(endpoint).build(provider);
        DecryptDataDetails decryptDataDetails = DecryptDataDetails.builder().keyId(keyOcid).ciphertext(cipherTextDEK).build();
        DecryptRequest decryptRequest = DecryptRequest.builder().decryptDataDetails(decryptDataDetails).build();
        DecryptResponse decryptResponse = cryptoClient.decrypt(decryptRequest);
        String decryptedDEK = decryptResponse.getDecryptedData().getPlaintext();

        String decryptedPassword = decrypt(encryptedPassword, decryptedDEK);

        /*
        * returning the decrypted password for demo
        * purposes only. in your production function,
        * obviously you should not do this.
        */
        return Map.of(
                "decryptedPassword",
                decryptedPassword
        );
    }

    private String decrypt(String encrypted, String key) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(original);
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
}