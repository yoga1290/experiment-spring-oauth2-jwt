package demo;

import java.util.UUID;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.access.annotation.Secured;
import java.security.Principal;

@SpringBootApplication
@EnableResourceServer
@EnableGlobalMethodSecurity(securedEnabled = true)
public class ResourceApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceApplication.class, args);
	}

}

@RestController
class Controller {
    @RequestMapping("/user")
    @Secured("ROLE_USER")
    public Principal home(Principal user) {
        return user;
    }
        
    @RequestMapping("/admin")
    @Secured("ROLE_ADMIN")
    public Principal admin(Principal user) {
        return user;
    }
}
