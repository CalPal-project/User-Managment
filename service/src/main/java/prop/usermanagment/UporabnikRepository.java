package prop.usermanagment;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UporabnikRepository extends JpaRepository<Uporabnik, Long> {
    
}