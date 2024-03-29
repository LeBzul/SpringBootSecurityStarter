package versusmind.connection.repository

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
import java.util.*


@Service
class PersonDetailsServiceImpl(private val applicationUserRepository: PersonRepository) : UserDetailsService {
    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(username: String): UserDetails {
        val applicationUser = applicationUserRepository.findByUsername(username)
                ?: throw UsernameNotFoundException(username)

        return User(applicationUser.username, applicationUser.password, Collections.singletonList(SimpleGrantedAuthority("User")))
    }
}