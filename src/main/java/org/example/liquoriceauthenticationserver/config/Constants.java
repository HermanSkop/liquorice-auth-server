package org.example.liquoriceauthenticationserver.config;

import io.jsonwebtoken.SignatureAlgorithm;

public class Constants {
    public final static int JWT_ACCESS_TOKEN_SECONDS_TIMEOUT_SKEW = 10;
    public static final SignatureAlgorithm JWT_SIGNATURE_ALGORITHM = SignatureAlgorithm.HS256;
    public static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-zA-Z])(?=.*[@#$%^&+=!])(?=\\S+$).{8,}$";
    public static final String PASSWORD_REGEX_MESSAGE = "Password must contain at least one letter, one number, one special character, and be at least 8 characters long.";

    public final static String BASE_PATH = "/auth";
    public static final String CLIENT_SERVER = "http://localhost:4200";
    public static final String OAUTH2_REDIRECT_PATH = "/oauth2/redirect";
}
