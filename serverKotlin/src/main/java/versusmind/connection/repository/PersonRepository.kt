package versusmind.connection.repository

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.repository.NoRepositoryBean
import org.springframework.stereotype.Repository
import versusmind.connection.security.CustomUserDetails
import versusmind.entity.Person


@Repository
interface PersonRepository : JpaRepository<Person, Int> {
    fun findByUsername(username: String) : Person
}