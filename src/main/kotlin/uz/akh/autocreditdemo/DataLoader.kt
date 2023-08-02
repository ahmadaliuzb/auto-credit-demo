package uz.akh.autocreditdemo

import org.springframework.boot.CommandLineRunner
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.stereotype.Component


/**
02/08/2023 - 6:17 PM
Created by Akhmadali
 */
@Component
class DataLoader(
    private val passwordEncoder: BCryptPasswordEncoder,
    private val userRepository: UserRepository
) : CommandLineRunner {
    override fun run(vararg args: String?) {


        userRepository.findByUsernameAndDeletedFalse("dev") ?: run {
            userRepository.save(
                User(
                    "Developiriddin",
                    "dev",
                    passwordEncoder.encode("123"),
                    "+998999041976",
                    Role.DEVELOPER
                )
            )
        }
    }
}