package org.example.liquoriceauthenticationserver.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.example.liquoriceauthenticationserver.config.Constants;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequestDto {
    @Email
    private String email;
    @Pattern(regexp = Constants.PASSWORD_REGEX, message = Constants.PASSWORD_REGEX_MESSAGE)
    private String password;
}
