package prop.usermanagment;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UporabnikRepository extends JpaRepository<Uporabnik, Long> {
    // Spring Data JPA samodejno implementira te metode
    Uporabnik findByUsername(String username);  // ✅ BREZ static!
    Uporabnik findByKeycloakId(String keycloakId);
}