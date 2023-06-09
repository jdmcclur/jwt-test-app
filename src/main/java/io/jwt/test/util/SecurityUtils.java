package io.jwt.test.util;

import java.io.FileInputStream;

import java.security.KeyStore;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

@ApplicationScoped
public class SecurityUtils {

  @Inject @ConfigProperty(name = "KEYSTORE_LOCATION", defaultValue = "/opt/key.p12")
  private String keyStoreLocation;

  //probably not a good idea to use as an env variable? But doing this for now.
  @Inject @ConfigProperty(name = "KEYSTORE_PASSWORD", defaultValue = "secret")
  private String keyStorePassword;

  @Inject @ConfigProperty(name = "KEYSTORE_ALIAS", defaultValue = "default")
  private String keyStoreAlias;

  @Inject @ConfigProperty(name = "JWT_ISSUER", defaultValue = "http://test")
  private String jwtIssuer;
  
  @Inject @ConfigProperty(name = "JWT_ALGORITHM", defaultValue = "RS256")
  private String jwtAlgorithm;

  @Inject @ConfigProperty(name = "ENCRYPT_JWT", defaultValue = "false")
  private boolean buildJWE;

  @Inject @ConfigProperty(name = "JWE_ALGORITHM_HEADER_VALUE", defaultValue = "RSA-OAEP")
  private String jweAlgorithmHeaderValue;

  @Inject @ConfigProperty(name = "JWE_ENC_METHOD_HEADER_PARAM", defaultValue = "A256GCM")
  private String encryptionMethodHeaderParameter;

  @Inject @ConfigProperty(name = "JWT_SUBJECT", defaultValue = "subject")
  private String jwtSubject;

  @Inject @ConfigProperty(name = "JWT_GROUP", defaultValue = "group")
  private String jwtGroup;

  private PrivateKey privateKey;
  private RSAPublicKey publicKey;

  @PostConstruct
  void init() {

    //Get the private key to generate JWTs and create the public JWK to send to the booking/customer service.
    try {
      FileInputStream is = new FileInputStream(keyStoreLocation);

      // For now use the p12 key generated for the service
      KeyStore keystore = KeyStore.getInstance("PKCS12");
      keystore.load(is, keyStorePassword.toCharArray());
      privateKey = (PrivateKey) keystore.getKey(keyStoreAlias, keyStorePassword.toCharArray());
      Certificate cert = keystore.getCertificate(keyStoreAlias);  
      publicKey = (RSAPublicKey) cert.getPublicKey();

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  /**
   *  Generate a JWT with login as the Subject. 
   * @throws JoseException 
   */
  public String generateJwt() throws JoseException {
    
    JwtClaims claims = new JwtClaims();
    claims.setIssuer(jwtIssuer);  

    claims.setExpirationTimeMinutesInTheFuture(60); 
    claims.setGeneratedJwtId(); 
    claims.setIssuedAtToNow(); 
    claims.setSubject(jwtSubject); 
    claims.setClaim("upn", jwtSubject); 
    List<String> groups = Arrays.asList(jwtGroup);
    claims.setStringListClaim("groups", groups);

    JsonWebSignature jws = new JsonWebSignature();
    jws.setPayload(claims.toJson());
    jws.setKey(privateKey);      
    jws.setAlgorithmHeaderValue(jwtAlgorithm);
    jws.setHeader("typ", "JWT");

    String jwsString = jws.getCompactSerialization();

    if (!buildJWE) {
      // return signed JWT.
      return jwsString;
    } 
      
    JsonWebEncryption jwe = new JsonWebEncryption();
    jwe.setAlgorithmHeaderValue(jweAlgorithmHeaderValue);
    jwe.setEncryptionMethodHeaderParameter(encryptionMethodHeaderParameter);

    jwe.setKey(publicKey);
    jwe.setContentTypeHeaderValue("JWT");
    jwe.setPayload(jwsString);

     // return JWE
     return jwe.getCompactSerialization();  
  }
}
