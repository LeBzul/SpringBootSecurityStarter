package versusmind.connection.service

import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service
import versusmind.connection.repository.PersonRepository
import versusmind.connection.security.CustomUserDetails

@Service(value = "userService")
open class CustomUserDetailsService (private val userRepository: PersonRepository) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        return CustomUserDetails(userRepository.findByUsername(username))
    }
}