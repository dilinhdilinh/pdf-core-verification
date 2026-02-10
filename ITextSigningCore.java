import com.itextpdf.io.image.*;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public class ITextSigningCore {
    private String ocspUrl;
    private String tsaUrl;

    public ITextSigningCore(String ocspUrl, String tsaUrl) {
        this.ocspUrl = ocspUrl;
        this.tsaUrl = tsaUrl;
    }

    public void executeSignature(String src, String dest, Certificate[] chain, PrivateKey pk, String provider, String reason, String location, BufferedImage appearanceImg) throws Exception {
        try (PdfReader reader = new PdfReader(src); FileOutputStream os = new FileOutputStream(dest)) {
            PdfSigner signer = new PdfSigner(reader, os, new StampingProperties().useAppendMode());
            String fieldName = "SIG_" + System.currentTimeMillis();
            signer.setFieldName(fieldName);

            PdfSignatureAppearance appearance = signer.getSignatureAppearance()
                    .setReason(reason).setLocation(location).setCertificate(chain[0])
                    .setSignatureGraphic(ImageDataFactory.create(appearanceImg, null))
                    .setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);

            Rectangle pageSize = signer.getDocument().getPage(1).getPageSizeWithRotation();
            float w = appearanceImg.getWidth() / 4f;
            float h = appearanceImg.getHeight() / 4f;
            appearance.setPageRect(new Rectangle(pageSize.getRight() - w - 5, pageSize.getTop() - h - 5, w, h)).setPageNumber(1);

            ITSAClient tsaClient = new CustomTSAClient(tsaUrl);
            IOcspClient ocspClient = new CustomOcspClient(ocspUrl);

            signer.signDetached(new BouncyCastleDigest(), new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider),
                    chain, null, ocspClient, tsaClient, 350000, PdfSigner.CryptoStandard.CMS);

            addDssInformation(dest, fieldName, chain, ((CustomOcspClient)ocspClient).getAllResponses());
        }
    }

    private void addDssInformation(String path, String field, Certificate[] chain, List<byte[]> ocsps) throws Exception {
        String tmp = path + ".tmp";
        try (PdfDocument pdf = new PdfDocument(new PdfReader(path), new PdfWriter(tmp), new StampingProperties().useAppendMode())) {
            PdfDictionary catalog = pdf.getCatalog().getPdfObject();
            PdfDictionary dss = new PdfDictionary();
            catalog.put(new PdfName("DSS"), dss);
            // Logic for DSS manual injection here...
        }
        java.nio.file.Files.move(java.nio.file.Paths.get(tmp), java.nio.file.Paths.get(path), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    private static class CustomOcspClient implements IOcspClient {
        private String url;
        private java.util.ArrayList<byte[]> responses = new java.util.ArrayList<>();
        public CustomOcspClient(String url) { this.url = url; }
        public List<byte[]> getAllResponses() { return responses; }
        @Override public byte[] getEncoded(X509Certificate c, X509Certificate i, String u) {
            // OCSP fetching logic...
            return null;
        }
    }

    private static class CustomTSAClient implements ITSAClient {
        private String url;
        public CustomTSAClient(String url) { this.url = url; }
        @Override public int getTokenSizeEstimate() { return 8192; }
        @Override public MessageDigest getMessageDigest() { try { return MessageDigest.getInstance("SHA-256"); } catch (Exception e) { return null; } }
        @Override public byte[] getTimeStampToken(byte[] imprint) throws Exception {
            // TSA fetching logic...
            return null;
        }
    }
}