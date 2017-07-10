package com.splunk.logging;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;

import javax.net.ssl.SSLContext;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import sun.security.provider.X509Factory;


/**
 * Created by ssergeev on 6/29/17.
 */
public class HttpEventCollectorSslUtils {
    final static String CLOUD_CERT_CONTENT = "-----BEGIN CERTIFICATE-----\nMIIB/DCCAaGgAwIBAgIBADAKBggqhkjOPQQDAjB+MSswKQYDVQQDEyJTcGx1bmsg\nQ2xvdWQgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNp\nc2NvMRMwEQYDVQQKEwpTcGx1bmsgSW5jMQswCQYDVQQIEwJDQTEVMBMGA1UECxMM\nU3BsdW5rIENsb3VkMB4XDTE0MTExMDA3MDAxOFoXDTM0MTEwNTA3MDAxOFowfjEr\nMCkGA1UEAxMiU3BsdW5rIENsb3VkIENlcnRpZmljYXRlIEF1dGhvcml0eTEWMBQG\nA1UEBxMNU2FuIEZyYW5jaXNjbzETMBEGA1UEChMKU3BsdW5rIEluYzELMAkGA1UE\nCBMCQ0ExFTATBgNVBAsTDFNwbHVuayBDbG91ZDBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPRRy9i3yQcxgMpvCSsI7Qe6YZMimUHOecPZWaGz5jEfB4+p5wT7dF3e\nQrgjDWshVJZvK6KGO7nDh97GnbVXrTCjEDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZI\nzj0EAwIDSQAwRgIhALMUgLYPtICN9ci/ZOoXeZxUhn3i4wIo2mPKEWX0IcfpAiEA\n8Jid6bzwUqAdDZPSOtaEBXV9uRIrNua0Qxl1S55TlWY=\n-----END CERTIFICATE-----\n";


    public static SSLContext build_cloud_trial_ssl_context() {
        return build_ssl_context(CLOUD_CERT_CONTENT);
    };

    public static SSLContext build_ssl_context(String cert_content) {
        try {


            // load certificate from file
//            System.out.println("cert_content: " + cert_content); // TODO remove this debug output
            X509Certificate cert = CertStrToX509(cert_content);
            System.out.println("cert: " + cert); // TODO remove this debug output

            // add cloudCA to the KetStore
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(null, null); // init an empty keystore
            keystore.setCertificateEntry("cloud.splunk.com", cert); // load cert to the hostname

            // set up sslContext
            SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(keystore,
                    new TrustSelfSignedStrategy()).build();
            return sslContext;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static CloseableHttpAsyncClient build_http_client_cloud_trail(int maxConnTotal) {

        SSLContext ssl_context  = HttpEventCollectorSslUtils.build_cloud_trial_ssl_context();

        return HttpAsyncClients.custom()
                .setMaxConnTotal(maxConnTotal)
                .setHostnameVerifier(SSLConnectionSocketFactory.STRICT_HOSTNAME_VERIFIER)
                .setSSLContext(ssl_context)
                .build();

    }
    private static X509Certificate CertStrToX509(String cert_content) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            String cert_content_stripped = cert_content
                    .replaceAll(X509Factory.BEGIN_CERT, "")
                    .replaceAll(X509Factory.END_CERT, "");
            byte [] decoded = Base64.decode(cert_content_stripped);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }
}
