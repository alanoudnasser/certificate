package com.example.certificate;


import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity {

    private TextView t1, t2, t3;

    static {
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Assuming you have TextViews with IDs R.id.text1, R.id.text2, and R.id.text3
        t1 = findViewById(R.id.text1);
        t2 = findViewById(R.id.text2);
        t3 = findViewById(R.id.text3);

        try {
            // Step 1: Come up with a message we want to encrypt
            byte[] message = "Hello, World!".getBytes();

            // Step 2: Create a KeyPairGenerator object
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            // Step 3: Initialize the KeyPairGenerator with a certain keysize
            keyPairGenerator.initialize(512);

            // Step 4: Generate the key pairs
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Step 5: Extract the keys
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            // Step 6: Create a digital certificate for the public key
            X509Certificate certificate = generateCertificate(publicKey, privateKey);

            // Step 7: Create a Cipher object
            Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");

            // Step 8: Initialize the Cipher object
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Step 9: Give the Cipher our message
            cipher.update(message);

            // Step 10: Encrypt the message
            byte[] ciphertext = cipher.doFinal();

            // Step 11: Display the results in TextViews
            t1.setText("Original Message: " + new String(message, "UTF8"));
            t2.setText("Encrypted Message: " + new String(ciphertext, "UTF8"));

            // Step 12: Change the Cipher object's mode
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Step 13: Give the Cipher object our ciphertext
            cipher.update(ciphertext);

            // Step 14: Decrypt the ciphertext
            byte[] decrypted = cipher.doFinal();

            // Step 15: Display the decrypted message in the new TextView
            t3.setText("Decrypted Message: " + new String(decrypted, "UTF8"));

            // Step 16: Verify the digital signature
            if (verifyDigitalSignature(certificate, publicKey)) {
                Log.d("Demo3", "Digital Signature Verified");
                // Step 17: Print the certificate
                String certificateString = certificate.toString();
                Log.d("Demo3", "Certificate:\n" + certificateString);
            } else {
                Log.d("Demo3", "Digital Signature Verification Failed");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to generate a digital certificate for the public key
    private X509Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey) throws Exception {
        // You may want to customize the certificate attributes based on your needs
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        X500Name issuerName = new X500Name("CN=Test Certificate");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30),
                new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10)),
                issuerName,
                keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());
        X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().getCertificate(certificateHolder);
    }

    // Method to verify the digital signature of the certificate
    private boolean verifyDigitalSignature(X509Certificate certificate, PublicKey publicKey) throws Exception {
        certificate.verify(publicKey);
        return true;
    }
}
