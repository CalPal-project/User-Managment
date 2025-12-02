package prop.usermanagment;

import org.springframework.web.bind.annotation.*;

@RestController
public class UsermanagmentApi {
    private final UporabnikRepository ur; 

    public UsermanagmentApi(UporabnikRepository ur){
        this.ur = ur;
    }

    @GetMapping("/api/getUser")
    public String getUser(int id){
        return "hello";
    }

    @PostMapping("/api/addUser")
    public Uporabnik addUser(@RequestBody Uporabnik user){
        return ur.save(user);
    }
}
