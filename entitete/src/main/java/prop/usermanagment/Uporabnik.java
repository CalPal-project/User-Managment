package prop.usermanagment;

import jakarta.persistence.*;

@Entity
@Table(name = "uporabnik")
public class Uporabnik {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ime;
    private String priimek;

    @Column(name = "uporabnisko_ime")
    private String username;

    private String email;
    
    
    
    @Column(name = "keycloak_id", unique = true, nullable = false)
    private String keycloakId;
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUporabniskoIme() { return username; }
    public void setUporabniskoIme(String username) { this.username = username; }
    
    public String getKeycloakId() { return keycloakId; }
    public void setKeycloakId(String keycloakId) { this.keycloakId = keycloakId; }
    
    // DTO method
    public UserDto toDto() {
        UserDto dto = new UserDto();
        dto.setId(this.id);
        dto.setUsername(this.username);
        return dto;
    }
    
    // DTO class
    public static class UserDto {
        private Long id;
        private String username;
        
        // Getters and Setters
        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
    }
}





// public class Uporabnik {
//     @Id
//     @GeneratedValue(strategy = GenerationType.IDENTITY)
//     private Integer id;
    
//     private String ime;
//     private String priimek;

//     @Column(name = "uporabnisko_ime")
//     private String uporabniskoIme;
//     private String email;
    
//     private String userId;
    
//     public Uporabnik(){

//     }
    
//     public Uporabnik(String uporabniskoIme, String ime, String priimek, String email){
//         this.uporabniskoIme = uporabniskoIme;
//         this.ime = ime;
//         this.priimek = priimek;
//         this.email = email;
//     }


//     public Integer getId() {
//         return id;
//     }

//     public void setId(Integer id) {
//         this.id = id;
//     }

//     public String getIme() {
//         return ime;
//     }

//     public void setIme(String ime) {
//         this.ime = ime;
//     }

//     public String getPriimek() {
//         return priimek;
//     }

//     public void setPriimek(String priimek) {
//         this.priimek = priimek;
//     }

//     public String getUporabniskoIme() {
//         return uporabniskoIme;
//     }

//     public void setUporabniskoIme(String uporabniskoIme) {
//         this.uporabniskoIme = uporabniskoIme;
//     }

//     public String getEmail() {
//         return email;
//     }

//     public void setEmail(String email) {
//         this.email = email;
//     }

//     public void setuserId(String s){
//         this.userId = s;
//     }

//     public String getuserId(){
//         return userId;
//     }
// }