package prop.usermanagment;
import jakarta.persistence.*;

@Entity
@Table(name = "uporabnik")

public class Uporabnik {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    
    private String ime;
    private String priimek;

    @Column(name = "uporabnisko_ime")
    private String uporabniskoIme;
    private String email;
    
    public Uporabnik(){

    }
    
    public Uporabnik(String uporabniskoIme, String ime, String priimek, String email){
        this.uporabniskoIme = uporabniskoIme;
        this.ime = ime;
        this.priimek = priimek;
        this.email = email;
    }


    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getIme() {
        return ime;
    }

    public void setIme(String ime) {
        this.ime = ime;
    }

    public String getPriimek() {
        return priimek;
    }

    public void setPriimek(String priimek) {
        this.priimek = priimek;
    }

    public String getUporabniskoIme() {
        return uporabniskoIme;
    }

    public void setUporabniskoIme(String uporabniskoIme) {
        this.uporabniskoIme = uporabniskoIme;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    // @Override
    // public String toString() {
    //     StringBuilder sb = new StringBuilder();
    //     sb.append("Ime: ");
    //     sb.append(this.ime);
    //     sb.append("<br/>Priimek: ");
    //     sb.append(this.priimek);
    //     sb.append("<br/>Uporabnisko ime: ");
    //     sb.append(this.uporabniskoIme);
    //     sb.append("<br/>Email: ");
    //     sb.append(this.email);
    //     return sb.toString();
    // }
}