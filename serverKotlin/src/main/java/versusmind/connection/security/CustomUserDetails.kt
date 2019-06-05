package versusmind.connection.security

import versusmind.entity.Person
import org.slf4j.LoggerFactory
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import java.util.*


open class CustomUserDetails(val person: Person) : User(person.username, person.password, Collections.singletonList(SimpleGrantedAuthority("User"))) {

    private val log = LoggerFactory.getLogger(CustomUserDetails::class.java)

    override fun getAuthorities(): Collection<GrantedAuthority> {
        return Collections.singletonList(SimpleGrantedAuthority("User"))
    }

    override fun isEnabled(): Boolean {
        return true
    }

    override fun getUsername(): String {
        return person.username
    }

    override fun getPassword(): String {
        return person.password
    }

    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    override fun isAccountNonExpired(): Boolean {
        return  true
    }

    override fun isAccountNonLocked(): Boolean {
        return true
    }
}
