import com.lbh.algorithm.GetKeyByP12File;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import static com.lbh.algorithm.Endorsement.checkTestSig;
import static com.lbh.algorithm.Endorsement.setSignature;

public class Test {
    public static void main(String[] args) throws UnrecoverableKeyException, CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        GetKeyByP12File alias = new GetKeyByP12File("C:\\Users\\libaiheng\\Desktop\\农商工作\\20060400000466904.p12", "111111", "alias");
        String privateKey = alias.getPrivateKey();
        String publicKey = alias.getPublicKey();

        System.out.println(privateKey);
        System.out.println(publicKey);

        String name = setSignature(privateKey, "黎佰恒");
        System.out.println(name);
        boolean libaiheng = checkTestSig(publicKey, "黎佰恒", name);
        System.out.println(libaiheng);

    }
}
