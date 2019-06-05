package versusmind.connection.security

import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import versusmind.connection.security.SecurityConstants.EXPIRATION_TIME
import versusmind.connection.security.SecurityConstants.HEADER_STRING
import versusmind.connection.security.SecurityConstants.SECRET
import versusmind.connection.security.SecurityConstants.TOKEN_PREFIX
import versusmind.entity.Person
import java.io.IOException
import java.util.*
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm.HMAC512
import com.google.gson.Gson
import org.springframework.security.core.userdetails.User


open class JWTAuthenticationFilter(var authManager: AuthenticationManager) : UsernamePasswordAuthenticationFilter() {

    @Throws(AuthenticationException::class)
    override fun attemptAuthentication(request: HttpServletRequest,
                                       response: HttpServletResponse): Authentication {
        try {
            val auth = authManager.authenticate(
                    UsernamePasswordAuthenticationToken(
                            obtainUsername(request),
                            obtainPassword(request),
                            ArrayList()))
            System.out.println("auth.isAuthenticated : ")
            System.out.println(auth.isAuthenticated)
            return auth
        } catch (e: IOException) {
            throw RuntimeException(e)
        }

    }

    override fun unsuccessfulAuthentication(request: HttpServletRequest?, response: HttpServletResponse?, failed: AuthenticationException?) {
        super.unsuccessfulAuthentication(request, response, failed)
    }

    @Throws(IOException::class, ServletException::class)
    override fun successfulAuthentication(req: HttpServletRequest,
                                           res: HttpServletResponse,
                                           chain: FilterChain,
                                           auth: Authentication) {

        val token = JWT.create()
                .withSubject((auth.principal as User).username ?: "")
                .withExpiresAt(Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(SECRET.toByteArray()))
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + token)

        chain.doFilter(req, res)
    }
}

object SecurityConstants {
    val SECRET = "SecretKeyToGenJWTs"
    val EXPIRATION_TIME: Long = 864000000 // 10 days
    val TOKEN_PREFIX = "Bearer "
    val HEADER_STRING = "Authorization"
    val SIGN_UP_URL = "/users/sign-up"
    val SIGN_IN_URL = "/users/login"
}