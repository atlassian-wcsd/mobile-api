/**
 * Interface representing a handwritten signature
 */
export interface Signature {
  /**
   * Unique identifier for the signature
   */
  id: string;

  /**
   * Base64 encoded image data of the handwritten signature
   */
  imageData: string;

  /**
   * Width of the signature in pixels
   */
  width: number;

  /**
   * Height of the signature in pixels
   */
  height: number;

  /**
   * Timestamp when the signature was created
   */
  createdAt: Date;

  /**
   * User ID of the person who created the signature
   */
  userId: string;

  /**
   * Optional description or label for the signature
   */
  label?: string;

  /**
   * Metadata about the signature creation
   */
  deviceInfo: {
    /**
     * Unique identifier for the device
     */
    deviceId: string;

    /**
     * Device used to create the signature (e.g., "tablet", "touchscreen", "signature-pad")
     */
    device: string;
    
    /**
     * Platform/OS information
     */
    platform: string;
    
    /**
     * Device verification status
     */
    verificationStatus: 'VERIFIED' | 'UNVERIFIED' | 'BLOCKED';

    /**
     * Authentication token for the device
     */
    authToken?: string;

    /**
     * Token expiration timestamp
     */
    tokenExpiration?: Date;
    
    /**
     * Pressure sensitivity data points if available
     */
    pressureData?: number[];
  };
}