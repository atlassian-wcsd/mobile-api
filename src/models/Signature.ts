/**
 * Interface representing a mobile handwritten signature
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
  metadata: {
    /**
     * Device used to create the signature (e.g., "tablet", "touchscreen", "signature-pad")
     */
    device: string;
    
    /**
     * Browser/platform information
     */
    platform: string;
    
    /**
     * Pressure sensitivity data points if available
     */
    pressureData?: number[];

    /**
     * Input method used (e.g., "finger", "stylus")
     */
    inputMethod: string;

    /**
     * Screen orientation when signature was created
     */
    screenOrientation: 'portrait' | 'landscape';

    /**
     * Device screen dimensions in pixels
     */
    screenDimensions: {
      width: number;
      height: number;
    };

    /**
     * Coordinates of signature strokes
     */
    strokeData?: Array<{
      points: Array<{
        x: number;
        y: number;
        timestamp: number;
        pressure?: number;
      }>;
    }>;

    /**
     * Mobile-specific device information
     */
    deviceInfo?: {
      model: string;
      os: string;
      osVersion: string;
      screenDPI: number;
    };

    /**
     * Geolocation data if available and permitted
     */
    location?: {
      latitude: number;
      longitude: number;
      accuracy: number;
    };
  };
}