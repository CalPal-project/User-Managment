package prop.usermanagment;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import jakarta.annotation.PostConstruct;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Service
public class KeycloakService {
    
    @Value("${keycloak.url}")
    private String keycloakUrl;
    
    @Value("${keycloak.realm}")
    private String keycloakRealm;
    
    @Value("${keycloak.admin.username}")
    private String keycloakAdmin;
    
    @Value("${keycloak.admin.password}")
    private String keycloakPassword;
    
    // DODAJ TEH DVEH SPREMENLJIVK - za client ID in secret
    @Value("${keycloak.client-id:calpal}") // Privzeto 'calpal' če ni nastavljeno
    private String clientId;
    
    // @Value("${keycloak.client-secret}") // To moraš dodati v application.properties
    // private String clientSecret;
    
    private JwkProvider jwkProvider;
    private RestTemplate restTemplate;
    private ObjectMapper objectMapper;
    
    // @PostConstruct
    // public void init() {
    //     String jwksUrl = String.format("%s/realms/%s/protocol/openid-connect/certs", 
    //                                    keycloakUrl, keycloakRealm);
    //     this.jwkProvider = new JwkProviderBuilder(jwksUrl).build();
    //     this.restTemplate = new RestTemplate();
    //     this.objectMapper = new ObjectMapper();
    // }
    @PostConstruct
public void init() {
    try {

        String jwksUrl = String.format(
            "%s/realms/%s/protocol/openid-connect/certs",
            keycloakUrl,
            keycloakRealm
        );

        System.out.println("JWKS URL = " + jwksUrl);

        // IMPORTANT: UrlJwkProvider does NOT modify the URL
        this.jwkProvider = new UrlJwkProvider(new URL(jwksUrl));

        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();

    } catch (Exception e) {
        throw new RuntimeException("Failed to initialize JWKS provider", e);
    }
}
    
    public String getKeycloakUrl() {
        return keycloakUrl;
    }
    
    public String getKeycloakRealm() {
        return keycloakRealm;
    }
    
    public String getAdminToken() {
        String url = String.format("%s/realms/master/protocol/openid-connect/token", keycloakUrl);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        String body = String.format("client_id=admin-cli&username=%s&password=%s&grant_type=password",
                                   keycloakAdmin, keycloakPassword);
        
        HttpEntity<String> request = new HttpEntity<>(body, headers);
        ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);
        
        try {
            JsonNode jsonNode = objectMapper.readTree(response.getBody());
            return jsonNode.get("access_token").asText();
        } catch (Exception e) {
            throw new RuntimeException("Failed to get admin token", e);
        }
    }
    
    public String getKeycloakUserId(String username, String adminToken) {
        String url = String.format("%s/admin/realms/%s/users?username=%s",
                                  keycloakUrl, keycloakRealm, username);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        
        HttpEntity<String> request = new HttpEntity<>(headers);
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, request, String.class);
        
        try {
            JsonNode users = objectMapper.readTree(response.getBody());
            if (users.isArray() && users.size() > 0) {
                return users.get(0).get("id").asText();
            }
            return null;
        } catch (Exception e) {
            throw new RuntimeException("Failed to get user ID", e);
        }
    }
public DecodedJWT validateToken(String token) {
    try {
        DecodedJWT decoded = JWT.decode(token);

        Jwk jwk = jwkProvider.get(decoded.getKeyId());
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("http://localhost:8080/realms/calpal")
                .acceptLeeway(5)
                .build();

        DecodedJWT verified = verifier.verify(token);

        System.out.println("✅ Token signature verified");
        System.out.println("Username: " + verified.getClaim("preferred_username").asString());

        return verified;

    } catch (Exception e) {
        System.out.println("❌ Token verification failed: " + e.getMessage());
        return null;
    }
}


    // POPRAVLJENA METODA - odstrani 'logger' in dodaj pravilen try-catch
    public Map<String, String> refreshToken(String refreshToken) {
        try {
            System.out.println("=== REFRESH TOKEN (without client-secret) ===");
            
            String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", 
                                          keycloakUrl, keycloakRealm);
            
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            
            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            // Brez client_secret za public client
            body.add("grant_type", "refresh_token");
            body.add("refresh_token", refreshToken);
            
            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
            
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            
            System.out.println("Refresh response status: " + response.getStatusCode());
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> responseBody = response.getBody();
                
                System.out.println("✅ Refresh successful");
                
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", (String) responseBody.get("access_token"));
                tokens.put("refresh_token", (String) responseBody.get("refresh_token"));
                tokens.put("expires_in", String.valueOf(responseBody.get("expires_in")));
                tokens.put("refresh_expires_in", String.valueOf(responseBody.get("refresh_expires_in")));
                
                return tokens;
            } else {
                System.out.println("❌ Refresh failed with status: " + response.getStatusCode());
            }
            
        } catch (Exception e) {
            System.out.println("❌ Error refreshing token: " + e.getMessage());
        }
        
        return null;
    }
}