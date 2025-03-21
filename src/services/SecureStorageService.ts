import { Platform } from 'react-native';
import EncryptedStorage from 'react-native-encrypted-storage';
import { AES, enc } from 'crypto-js';

/**
 * Service for securely storing and retrieving sensitive data
 */
export class SecureStorageService {
  private static instance: SecureStorageService;
  private readonly encryptionKey: string;

  private constructor() {
    // Generate or retrieve a secure encryption key
    this.encryptionKey = process.env.ENCRYPTION_KEY || 'your-secure-key-here';
  }

  /**
   * Get singleton instance of SecureStorageService
   */
  public static getInstance(): SecureStorageService {
    if (!SecureStorageService.instance) {
      SecureStorageService.instance = new SecureStorageService();
    }
    return SecureStorageService.instance;
  }

  /**
   * Securely store data with encryption
   * @param key Storage key
   * @param value Data to store
   */
  public async storeSecureData(key: string, value: any): Promise<void> {
    try {
      const encryptedValue = this.encrypt(JSON.stringify(value));
      await EncryptedStorage.setItem(key, encryptedValue);
    } catch (error) {
      console.error('Error storing secure data:', error);
      throw new Error('Failed to store secure data');
    }
  }

  /**
   * Retrieve securely stored data
   * @param key Storage key
   * @returns Decrypted data
   */
  public async getSecureData(key: string): Promise<any> {
    try {
      const encryptedValue = await EncryptedStorage.getItem(key);
      if (!encryptedValue) return null;

      const decryptedValue = this.decrypt(encryptedValue);
      return JSON.parse(decryptedValue);
    } catch (error) {
      console.error('Error retrieving secure data:', error);
      throw new Error('Failed to retrieve secure data');
    }
  }

  /**
   * Remove securely stored data
   * @param key Storage key
   */
  public async removeSecureData(key: string): Promise<void> {
    try {
      await EncryptedStorage.removeItem(key);
    } catch (error) {
      console.error('Error removing secure data:', error);
      throw new Error('Failed to remove secure data');
    }
  }

  /**
   * Clear all securely stored data
   */
  public async clearSecureStorage(): Promise<void> {
    try {
      await EncryptedStorage.clear();
    } catch (error) {
      console.error('Error clearing secure storage:', error);
      throw new Error('Failed to clear secure storage');
    }
  }

  /**
   * Encrypt data using AES encryption
   * @param data Data to encrypt
   * @returns Encrypted string
   */
  private encrypt(data: string): string {
    return AES.encrypt(data, this.encryptionKey).toString();
  }

  /**
   * Decrypt data using AES decryption
   * @param encryptedData Encrypted data to decrypt
   * @returns Decrypted string
   */
  private decrypt(encryptedData: string): string {
    const bytes = AES.decrypt(encryptedData, this.encryptionKey);
    return bytes.toString(enc.Utf8);
  }

  /**
   * Store user session data securely
   * @param sessionData User session data
   */
  public async storeUserSession(sessionData: {
    token: string;
    userId: string;
    expiresAt: number;
  }): Promise<void> {
    await this.storeSecureData('userSession', sessionData);
  }

  /**
   * Retrieve user session data
   * @returns User session data
   */
  public async getUserSession(): Promise<{
    token: string;
    userId: string;
    expiresAt: number;
  } | null> {
    return await this.getSecureData('userSession');
  }

  /**
   * Clear user session data
   */
  public async clearUserSession(): Promise<void> {
    await this.removeSecureData('userSession');
  }
}