package demo;
import java.security.Principal;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
/**
 *
 * @author yoga1290
 */
@Controller
public class UserController {

    @RequestMapping("/user")
    @ResponseBody
    @Secured("ROLE_USER")
    public Principal user(Principal user) {
        return user;
    }
    
    @RequestMapping("/admin")
    @ResponseBody
    @Secured("ROLE_ADMIN")
    public Principal admin(Principal user) {
        return user;
    }
}
