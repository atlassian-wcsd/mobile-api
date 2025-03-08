const bcrypt = require('bcrypt');

const SALT_ROUNDS = 10;

/**
  * Hashes a password using bcrypt.
  * @param {string} password - The password to hash.
  * @returns {Promise<string>} - A promise that resolves to the hashed password.
  */
async function hashPassword(password) {
    try {
        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        const hashedPassword = await bcrypt.hash(password, salt);
        return hashedPassword;
    } catch (error) {
        throw new Error('Error hashing password');
    }
}

/**
  * Compares a plain password with a hashed password.
  * @param {string} password - The plain password.
  * @param {string} hashedPassword - The hashed password.
  * @returns {Promise<boolean>} - A promise that resolves to true if the passwords match, false otherwise.
  */
async function comparePassword(password, hashedPassword) {
    try {
        return await bcrypt.compare(password, hashedPassword);
    } catch (error) {
        throw new Error('Error comparing passwords');
    }
}

module.exports = {
    hashPassword,
    comparePassword
};
