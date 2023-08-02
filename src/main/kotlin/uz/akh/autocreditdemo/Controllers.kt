package uz.akh.autocreditdemo

import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.*


/**
02/08/2023 - 4:50 PM
Created by Akhmadali
 */
@CrossOrigin(origins = ["*"], maxAge = 3600)
@RestController
@RequestMapping("/users")
class UserController(
    private val authenticationManager: AuthenticationManager,
    private val jwtTokenUtil: TokenProvider,
    private val userService: UserService
) {


    @RequestMapping(value = ["/authenticate"], method = [RequestMethod.POST])
    fun generateToken(@RequestBody loginUser: LoginUser): ResponseEntity<*> {
        val authentication = authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(
                loginUser.username,
                loginUser.password
            )
        )
        SecurityContextHolder.getContext().authentication = authentication
        val token = jwtTokenUtil.generateToken(authentication)
        return ResponseEntity.ok<Any>(AuthToken(token))
    }
    @PreAuthorize("hasRole('DEVELOPER')")
    @RequestMapping(value = ["/register"], method = [RequestMethod.POST])
    fun saveUser(@RequestBody userDto: UserDto): User {
        return userService.save(userDto)
    }

    @PreAuthorize("hasRole('ADMIN')")
    @RequestMapping(value = ["/adminping"], method = [RequestMethod.GET])
    fun adminPing(): String {
        return "Only Admins Can Read This"
    }

    @PreAuthorize("hasRole('USER')")
    @RequestMapping(value = ["/userping"], method = [RequestMethod.GET])
    fun userPing(): String {
        return "Any User Can Read This"
    }
}
