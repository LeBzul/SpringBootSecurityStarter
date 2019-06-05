package versusmind.connection.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import versusmind.connection.repository.PersonDetailsServiceImpl
import versusmind.connection.security.SecurityConstants.SIGN_UP_URL
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import versusmind.connection.security.SecurityConstants.SIGN_IN_URL
import org.springframework.security.web.authentication.HttpStatusEntryPoint
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.NegatedRequestMatcher
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher






@EnableWebSecurity
open class WebSecurity : WebSecurityConfigurerAdapter() {

    @Autowired
    var userDetailsService: PersonDetailsServiceImpl? = null

    var bCryptPasswordEncoder: BCryptPasswordEncoder? = null

    init {
        bCryptPasswordEncoder = BCryptPasswordEncoder()
    }


    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {

        val filterJWTAuthentication = JWTAuthenticationFilter(authenticationManager())
        filterJWTAuthentication.setFilterProcessesUrl(SIGN_IN_URL)

        http
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers(SIGN_UP_URL, SIGN_IN_URL).permitAll()
                .anyRequest().authenticated()
                .and()
               // .addFilter(JWTAuthorizationFilter(authenticationManager()))
                .addFilter(filterJWTAuthentication)
    }


    @Throws(Exception::class)
    public override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService<UserDetailsService>(userDetailsService).passwordEncoder(bCryptPasswordEncoder)
    }

    @Bean
    open fun corsConfigurationSource(): CorsConfigurationSource {
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", CorsConfiguration().applyPermitDefaultValues())
        return source
    }

    @Bean
    open fun forbiddenEntryPoint(): AuthenticationEntryPoint {
        return HttpStatusEntryPoint(org.springframework.http.HttpStatus.FORBIDDEN)
    }
}