package uz.akh.autocreditdemo


/**
02/08/2023 - 5:52 PM
Created by Akhmadali
 */

data class AuthToken(
    var token: String
)

data class LoginUser(
    var username: String,
    var password: String
)

data class UserDto(

    var fullName: String,

    var username: String,

    val password: String,


    val phone: String,

    val role: String,


    ) {
    companion object {
        fun toDto(user: User) = user.run {
            UserDto(
                fullName,
                username,
                password,
                phone,
                role.name
            )
        }
    }

    fun toEntity(): User {
        val roleEnum = when (role) {
            "ADMIN" -> Role.ADMIN
            "DEVELOPER" -> Role.DEVELOPER
            else -> Role.USER
        }
        return User(
            fullName,
            username,
            password,
            phone,
            roleEnum
        )
    }
}