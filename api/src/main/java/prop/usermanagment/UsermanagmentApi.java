package prop.usermanagment;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@CrossOrigin(origins = "*")  // Dovoli vse origins
@RestController
@RequestMapping("/api/auth")
public class UsermanagmentApi {
    
    @Autowired
    private KeycloakService keycloakService;
    
    @Autowired
    private UporabnikRepository userRepository;



    @Autowired
    public UsermanagmentApi(KeycloakService keycloakService, UporabnikRepository userRepository) {
        this.keycloakService = keycloakService;
        this.userRepository = userRepository;
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        System.out.println("Login for: " + request.username);
        
        String url = String.format("%s/realms/%s/protocol/openid-connect/token",keycloakService.getKeycloakUrl(),keycloakService.getKeycloakRealm());
        System.out.println("URL: " + url);
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        
        String body = String.format("client_id=calpal&username=%s&password=%s&grant_type=password",request.username, request.password);
        
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
            System.out.println("Response status: " + response.getStatusCode());
            
            ObjectMapper mapper = new ObjectMapper();
            JsonNode tokenResponse = mapper.readTree(response.getBody());

            Uporabnik user = userRepository.findByUsername(request.username);
            System.out.println("User from DB: " + (user != null ? user.getUporabniskoIme() : "null"));
            
            if (user == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "User exists in Keycloak but not in local DB"));
            }
            
            Map<String, Object> result = new HashMap<>();
            result.put("access_token", tokenResponse.get("access_token").asText());
            result.put("refresh_token", tokenResponse.get("refresh_token").asText());
            result.put("expires_in", tokenResponse.get("expires_in").asInt());
            result.put("user", user.toDto());
            
            return ResponseEntity.ok(result);
            
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Napačno uporabniško ime ali geslo"));
        }
    }
    
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        // Get admin token
        String adminToken = keycloakService.getAdminToken();
        
        // Create user in Keycloak
        String url = String.format("%s/admin/realms/%s/users",keycloakService.getKeycloakUrl(),keycloakService.getKeycloakRealm());
        
        Map<String, Object> userPayload = new HashMap<>();
        userPayload.put("username", request.getUsername());
        userPayload.put("enabled", true);
        userPayload.put("firstName", request.getFirstName());
        userPayload.put("lastName", request.getLastName());
        userPayload.put("email", request.getEmail());
        userPayload.put("emailVerified", true);
        
        Map<String, Object> credential = new HashMap<>();
        credential.put("type", "password");
        credential.put("value", request.getPassword());
        credential.put("temporary", false);
        
        userPayload.put("credentials", new Map[]{credential});
        
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(userPayload, headers);
        RestTemplate restTemplate = new RestTemplate();
        
        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, entity, String.class);
            
            if (response.getStatusCode() == HttpStatus.CREATED) {
                String keycloakId = keycloakService.getKeycloakUserId(request.getUsername(), adminToken);
                
                if (keycloakId == null) {
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("status", "error", "detail", "Could not fetch user ID"));
                }
                
                Uporabnik user = new Uporabnik();
                user.setKeycloakId(keycloakId);
                user.setUporabniskoIme(request.getUsername());
                user.setemail(request.getEmail());
                user.setlastName(request.getLastName());
                user.setname(request.getFirstName());
                userRepository.save(user);
                
                String loginUrl = String.format("%s/realms/%s/protocol/openid-connect/token",keycloakService.getKeycloakUrl(),keycloakService.getKeycloakRealm());
                
                HttpHeaders loginHeaders = new HttpHeaders();
                loginHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                
                String loginBody = String.format("client_id=calpal&username=%s&password=%s&grant_type=password",request.getUsername(), request.getPassword());
                
                HttpEntity<String> loginEntity = new HttpEntity<>(loginBody, loginHeaders);
                ResponseEntity<String> loginResponse = restTemplate.postForEntity(loginUrl, loginEntity, String.class);
                
                ObjectMapper mapper = new ObjectMapper();
                JsonNode tokenResponse = mapper.readTree(loginResponse.getBody());
                
                Map<String, Object> result = new HashMap<>();
                result.put("username", request.getUsername());
                result.put("access_token", tokenResponse.get("access_token").asText());
                result.put("refresh_token", tokenResponse.get("refresh_token").asText());
                
                return ResponseEntity.status(HttpStatus.CREATED).body(result);
                
            } else if (response.getStatusCode() == HttpStatus.CONFLICT) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("status", "user already exists"));
            } else {
                return ResponseEntity.status(response.getStatusCode()).body(Map.of("status", "error", "detail", response.getBody()));
            }
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("status", "error", "detail", e.getMessage()));
        }
    }
    
    @GetMapping("/validate_token")
    public ResponseEntity<?> validateToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "missing token"));
        }
        
        String token = authHeader.substring(7);
        DecodedJWT decodedJWT = keycloakService.validateToken(token);
        
        if (decodedJWT == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid token"));
        }
        
        return ResponseEntity.ok(Map.of(
            "message", "access granted",
            "user", decodedJWT.getClaim("preferred_username").asString()
        ));
    }

    @GetMapping("/getUser")
    public ResponseEntity<?> getUser(@RequestHeader("Authorization") String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "missing token"));
            }
            
            String token = authHeader.substring(7);
            
            DecodedJWT decodedJWT = keycloakService.validateToken(token);
            
            if (decodedJWT == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid or expired token"));
            }
            
            String username = decodedJWT.getClaim("preferred_username").asString();
            String email = decodedJWT.getClaim("email").asString();
            String firstName = decodedJWT.getClaim("given_name").asString();
            String lastName = decodedJWT.getClaim("family_name").asString();
            String userId = decodedJWT.getSubject();
            
            Uporabnik user = userRepository.findByUsername(username);
            
            if (user == null) {
                Map<String, Object> userInfo = new HashMap<>();
                userInfo.put("username", username);
                userInfo.put("email", email);
                userInfo.put("firstName", firstName);
                userInfo.put("lastName", lastName);
                userInfo.put("keycloakId", userId);
                userInfo.put("source", "token_only");
                
                return ResponseEntity.ok(Map.of(
                    "user", userInfo,
                    "tokenInfo", Map.of(
                        "expiresAt", decodedJWT.getExpiresAt(),
                        "issuedAt", decodedJWT.getIssuedAt(),
                        "issuer", decodedJWT.getIssuer()
                    )
                ));
            }

            Map<String, Object> response = new HashMap<>();
            response.put("user", user.toDto());
            response.put("tokenInfo", Map.of(
                "expiresAt", decodedJWT.getExpiresAt(),
                "issuedAt", decodedJWT.getIssuedAt(),
                "issuer", decodedJWT.getIssuer()
            ));
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            System.out.println("ERROR getting user info: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Failed to get user information"));
        }
    }
    
}