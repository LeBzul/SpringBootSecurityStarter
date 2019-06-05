package versusmind.connection.controller

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.codehaus.jackson.map.ObjectMapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.userdetails.User
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.web.bind.annotation.*
import versusmind.connection.repository.PersonRepository
import versusmind.connection.security.CustomUserDetails
import versusmind.connection.security.SecurityConstants
import versusmind.entity.Person
import java.util.*


@RestController
@RequestMapping("/users")
class LoginController {

    @Autowired
    var personRespository: PersonRepository? = null

    var bCryptPasswordEncoder  = BCryptPasswordEncoder()

    @PostMapping("/sign-up")
    fun signUp(@RequestBody person: Person) {
        person.password = (bCryptPasswordEncoder.encode(person.password))
        personRespository?.save(person)
    }

    @PostMapping("/login")
    fun login(@RequestBody person: Person) : ResponseEntity<CustomUserDetails> {
        personRespository?.findByUsername(person.username)?.let {
            var res = ResponseEntity<CustomUserDetails>(CustomUserDetails(it), HttpStatus.ACCEPTED)
            return res
        } ?: run {
            return  ResponseEntity<CustomUserDetails>(null, HttpStatus.NOT_FOUND)
        }
    }

    @PostMapping("/login2")
    fun login2(@RequestBody person: Person) : ResponseEntity<CustomUserDetails> {
        personRespository?.findByUsername("Guillian")?.let {
            return ResponseEntity<CustomUserDetails>(CustomUserDetails(it), HttpStatus.ACCEPTED)
        } ?: run {
            return  ResponseEntity<CustomUserDetails>(null, HttpStatus.NOT_FOUND)
        }
    }
}