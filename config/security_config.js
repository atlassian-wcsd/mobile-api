module.exports = {
  passwordPolicy: {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialCharacters: true,
    maxPasswordAge: 90, // days
    passwordReusePrevention: 5, // number of previous passwords disallowed
    lockoutThreshold: 5, // number of failed attempts before lockout
    lockoutDuration: 30, // minutes
  }
};
