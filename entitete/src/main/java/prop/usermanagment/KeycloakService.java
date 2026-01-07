package prop.usermanagment;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import jakarta.annotation.PostConstruct;
import java.security.interfaces.RSAPublicKey;

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
    
    private JwkProvider jwkProvider;
    private RestTemplate restTemplate;
    private ObjectMapper objectMapper;
    
    public String getKeycloakUrl() {
        return keycloakUrl;
    }
    
    public String getKeycloakRealm() {
        return keycloakRealm;
    }
    
    @PostConstruct
    public void init() {
        String jwksUrl = String.format("%s/realms/%s/protocol/openid-connect/certs", 
                                       keycloakUrl, keycloakRealm);
        this.jwkProvider = new JwkProviderBuilder(jwksUrl).build();
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
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
            // Get the signing key from JWKS
            DecodedJWT jwt = JWT.decode(token);
            Jwk jwk = jwkProvider.get(jwt.getKeyId());
            RSAPublicKey publicKey = (RSAPublicKey) jwk.getPublicKey();
            
            // Create verifier
            Algorithm algorithm = Algorithm.RSA256(publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(String.format("%s/realms/%s", keycloakUrl, keycloakRealm))
                    .acceptExpiresAt(5) // 5 seconds leeway
                    .build();
            
            // Verify token
            DecodedJWT verifiedJwt = verifier.verify(token);
            
            // Check authorized party (azp)
            if (!"kupiskupi".equals(verifiedJwt.getClaim("azp").asString())) {
                return null;
            }
            
            return verifiedJwt;
            
        } catch (Exception e) {
            return null;
        }
    }
}