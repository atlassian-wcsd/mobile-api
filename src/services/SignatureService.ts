import { Signature } from '../models/Signature';

/**
 * Service class for managing handwriting signatures
 */
export class SignatureService {
  private signatures: Map<string, Signature> = new Map();
  private authenticatedDevices: Map<string, { authToken: string; expiration: Date }> = new Map();

  /**
   * Authenticate a mobile device
   * @param deviceId Unique identifier for the device
   * @param deviceFingerprint Device information for verification
   * @returns Authentication token if successful, null if authentication fails
   */
  public authenticateDevice(
    deviceId: string,
    deviceFingerprint: {
      platform: string;
      osVersion: string;
      appVersion: string;
      deviceModel: string;
    }
  ): { authToken: string; expiresIn: number } | null {
    // Validate device fingerprint
    if (!this.validateDeviceFingerprint(deviceFingerprint)) {
      return null;
    }

    // Generate authentication token
    const authToken = this.generateAuthToken();
    const expiresIn = 24 * 60 * 60; // 24 hours in seconds
    const expiration = new Date(Date.now() + expiresIn * 1000);

    // Store device authentication
    this.authenticatedDevices.set(deviceId, { authToken, expiration });

    return { authToken, expiresIn };
  }

  /**
   * Validate a device's authentication token
   * @param deviceId Device identifier
   * @param authToken Authentication token to validate
   * @returns true if the token is valid, false otherwise
   */
  public validateDeviceAuth(deviceId: string, authToken: string): boolean {
    const deviceAuth = this.authenticatedDevices.get(deviceId);
    if (!deviceAuth) return false;

    return deviceAuth.authToken === authToken && deviceAuth.expiration > new Date();
  }

  /**
   * Validate device fingerprint information
   * @param fingerprint Device fingerprint data
   * @returns true if the fingerprint is valid, false otherwise
   */
  private validateDeviceFingerprint(fingerprint: {
    platform: string;
    osVersion: string;
    appVersion: string;
    deviceModel: string;
  }): boolean {
    // Implement device fingerprint validation logic
    return (
      !!fingerprint.platform &&
      !!fingerprint.osVersion &&
      !!fingerprint.appVersion &&
      !!fingerprint.deviceModel
    );
  }

  /**
   * Generate a secure authentication token
   * @returns A unique authentication token
   */
  private generateAuthToken(): string {
    return 'auth_' + Date.now() + '_' + crypto.randomUUID();
  }

  /**
   * Create a new handwriting signature
   * @param imageData Base64 encoded image data of the signature
   * @param width Width of the signature in pixels
   * @param height Height of the signature in pixels
   * @param userId ID of the user creating the signature
   * @param metadata Device and platform information
   * @param label Optional label for the signature
   * @returns The created signature object
   */
  public createSignature(
    imageData: string,
    width: number,
    height: number,
    userId: string,
    deviceInfo: {
      deviceId: string;
      device: string;
      platform: string;
      verificationStatus: 'VERIFIED' | 'UNVERIFIED' | 'BLOCKED';
      authToken?: string;
      pressureData?: number[];
    },
    label?: string
  ): Signature {
    // Validate device authentication before creating signature
    if (!deviceInfo.authToken || !this.validateDeviceAuth(deviceInfo.deviceId, deviceInfo.authToken)) {
      throw new Error('Device authentication required');
    }

    const signature: Signature = {
      id: this.generateSignatureId(),
      imageData,
      width,
      height,
      createdAt: new Date(),
      userId,
      deviceInfo: {
        ...deviceInfo,
        verificationStatus: this.getDeviceVerificationStatus(deviceInfo.deviceId)
      },
      label
    };

    this.signatures.set(signature.id, signature);
    return signature;
  }

  /**
   * Retrieve a signature by its ID
   * @param signatureId The ID of the signature to retrieve
   * @returns The signature object if found, null otherwise
   */
  public getSignature(signatureId: string): Signature | null {
    return this.signatures.get(signatureId) || null;
  }

  /**
   * Get all signatures for a specific user
   * @param userId The ID of the user
   * @returns Array of signatures belonging to the user
   */
  public getUserSignatures(userId: string): Signature[] {
    return Array.from(this.signatures.values())
      .filter(signature => signature.userId === userId);
  }

  /**
   * Update the label of an existing signature
   * @param signatureId The ID of the signature to update
   * @param newLabel The new label for the signature
   * @returns The updated signature if found, null otherwise
   */
  public updateSignatureLabel(signatureId: string, newLabel: string): Signature | null {
    const signature = this.signatures.get(signatureId);
    if (!signature) return null;

    signature.label = newLabel;
    this.signatures.set(signatureId, signature);
    return signature;
  }

  /**
   * Delete a signature
   * @param signatureId The ID of the signature to delete
   * @returns true if the signature was deleted, false if it wasn't found
   */
  public deleteSignature(signatureId: string): boolean {
    return this.signatures.delete(signatureId);
  }

  /**
   * Validate if the provided image data is a valid signature
   * @param imageData Base64 encoded image data to validate
   * @returns true if the image data is valid, false otherwise
   */
  public validateSignatureImage(imageData: string): boolean {
    // Basic validation to check if the string is a valid base64 image
    try {
      if (!imageData.startsWith('data:image/')) {
        return false;
      }
      const base64Data = imageData.split(',')[1];
      return !!base64Data && base64Data.length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Generate a unique signature ID
   * @returns A unique string ID
   */
  private generateSignatureId(): string {
    return 'sig_' + Date.now() + '_' + crypto.randomUUID();
  }

  /**
   * Get the verification status for a device
   * @param deviceId Device identifier
   * @returns The verification status of the device
   */
  private getDeviceVerificationStatus(deviceId: string): 'VERIFIED' | 'UNVERIFIED' | 'BLOCKED' {
    const deviceAuth = this.authenticatedDevices.get(deviceId);
    if (!deviceAuth) return 'UNVERIFIED';
    
    // Check if the device's authentication is expired
    if (deviceAuth.expiration < new Date()) {
      return 'UNVERIFIED';
    }

    // In a real implementation, additional checks would be performed here
    // such as checking against a blocklist, verifying device integrity, etc.
    return 'VERIFIED';
  }
}