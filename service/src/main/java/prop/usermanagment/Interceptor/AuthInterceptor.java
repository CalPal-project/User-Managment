package prop.usermanagment.Interceptor;
import prop.usermanagment.KeycloakService;
import prop.usermanagment.Annotation.Protected;


import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthInterceptor implements HandlerInterceptor {
    
    @Autowired
    private KeycloakService keycloakService;
    
    @Override
    public boolean preHandle(HttpServletRequest request, 
                            HttpServletResponse response, 
                            Object handler) throws Exception {
        
        if (!(handler instanceof HandlerMethod)) {
            return true;
        }
        
        HandlerMethod handlerMethod = (HandlerMethod) handler;
        Method method = handlerMethod.getMethod();
        
        // POPRAVEK: Pravilno preverjanje anotacije
        Protected protectedAnnotation = method.getAnnotation(Protected.class);
        if (protectedAnnotation == null) {
            // Preveri tudi na nivoju razreda (če je cel controller zaščiten)
            protectedAnnotation = method.getDeclaringClass().getAnnotation(Protected.class);
        }
        
        if (protectedAnnotation == null) {
            return true; // Metoda ni zaščitena
        }
        
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "missing token");
            
            ObjectMapper mapper = new ObjectMapper();
            response.getWriter().write(mapper.writeValueAsString(error));
            return false;
        }
        
        String token = authHeader.substring(7);
        DecodedJWT decodedJWT = keycloakService.validateToken(token);
        
        if (decodedJWT == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            
            Map<String, String> error = new HashMap<>();
            error.put("error", "invalid token");
            
            ObjectMapper mapper = new ObjectMapper();
            response.getWriter().write(mapper.writeValueAsString(error));
            return false;
        }
        
        // Add user info to request attributes
        request.setAttribute("user", decodedJWT.getClaim("preferred_username").asString());
        request.setAttribute("userClaims", decodedJWT.getClaims());
        
        return true;
    }
}