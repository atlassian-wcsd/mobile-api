const bcrypt = require('bcrypt');

const SALT_ROUNDS = 10;

/**
  * Hashes a plain text password.
  * @param {string} password - The plain text password.
  * @returns {Promise<string>} - A promise that resolves to the hashed password.
  */
async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
}

/**
  * Compares a plain text password with a hashed password.
  * @param {string} password - The plain text password.
  * @param {string} hashedPassword - The hashed password.
  * @returns {Promise<boolean>} - A promise that resolves to true if the passwords match, false otherwise.
  */
async function verifyPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}

module.exports = {
    hashPassword,
    verifyPassword
};
