package com.rksdev.security.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.regex.Pattern;

public class PasswordStrengthValidator implements ConstraintValidator<ValidPassword, String> {

    // RegEx breakdown:
    // ^                 = Start of string
    // (?=.*[0-9])       = Must contain at least one digit
    // (?=.*[a-z])       = Must contain at least one lowercase letter
    // (?=.*[A-Z])       = Must contain at least one uppercase letter
    // (?=.*[@#$%^&+=!]) = Must contain at least one special character
    // \S+$              = No whitespace allowed
    // .{8,}             = Minimum 8 characters long
    private static final String PASSWORD_REGEX = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!])\\S+$";
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(PASSWORD_REGEX);

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) {
            return false;
        }

        // Enforce a strict minimum length boundary alongside the regex pattern check
        if (password.length() < 8) {
            return false;
        }

        return PASSWORD_PATTERN.matcher(password).matches();
    }
}