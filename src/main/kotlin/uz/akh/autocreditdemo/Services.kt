package uz.akh.autocreditdemo

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Service


/**
02/08/2023 - 5:47 PM
Created by Akhmadali
 */

interface UserService {
    fun save(userDto: UserDto): User
}

@Service
class UserServiceImpl(
    private val userRepository: UserRepository,
    private val bcryptEncoder: BCryptPasswordEncoder
) : UserDetailsService, UserService {


    override fun loadUserByUsername(username: String): UserDetails {
        val user: User =
            userRepository.findByUsernameAndDeletedFalse(username)
                ?: throw UsernameNotFoundException("Invalid username or password.")
        return org.springframework.security.core.userdetails.User(
            user.username,
            user.password,
            getAuthority(user)
        )
    }

    private fun getAuthority(user: User): Set<SimpleGrantedAuthority> {
        val authorities: MutableSet<SimpleGrantedAuthority> = HashSet()
        authorities.add(SimpleGrantedAuthority("ROLE_" + user.role.name))
        return authorities
    }


    override fun save(userDto: UserDto): User {
        val nUser: User = userDto.toEntity()
        nUser.password = bcryptEncoder.encode(userDto.password)
        return userRepository.save(nUser)
    }
}

