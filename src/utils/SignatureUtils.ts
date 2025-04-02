import { Signature } from '../models/Signature';

/**
 * Utility functions for handling mobile handwriting signatures
 */
export class SignatureUtils {
  /**
   * Validates if a signature object meets all required criteria
   * @param signature The signature object to validate
   * @returns boolean indicating if the signature is valid
   */
  static isValidSignature(signature: Signature): boolean {
    if (!signature) return false;

    return !!(
      signature.id &&
      signature.imageData &&
      signature.width > 0 &&
      signature.height > 0 &&
      signature.createdAt &&
      signature.userId &&
      signature.metadata &&
      signature.metadata.device &&
      signature.metadata.platform &&
      signature.metadata.inputMethod &&
      signature.metadata.screenOrientation &&
      signature.metadata.screenDimensions
    );
  }

  /**
   * Converts a base64 signature image to a Blob
   * @param signature The signature containing base64 image data
   * @returns Blob of the signature image
   */
  static signatureToBlob(signature: Signature): Blob {
    const base64Data = signature.imageData.split(',')[1] || signature.imageData;
    const byteCharacters = atob(base64Data);
    const byteArrays = [];

    for (let offset = 0; offset < byteCharacters.length; offset += 512) {
      const slice = byteCharacters.slice(offset, offset + 512);
      const byteNumbers = new Array(slice.length);
      
      for (let i = 0; i < slice.length; i++) {
        byteNumbers[i] = slice.charCodeAt(i);
      }
      
      const byteArray = new Uint8Array(byteNumbers);
      byteArrays.push(byteArray);
    }

    return new Blob(byteArrays, { type: 'image/png' });
  }

  /**
   * Creates a new signature metadata object with default values
   * @param device The device type used for signature capture
   * @param inputMethod The input method used (finger/stylus)
   * @returns Default metadata object for a signature
   */
  static createDefaultMetadata(
    device: string,
    inputMethod: string
  ): Signature['metadata'] {
    return {
      device,
      platform: navigator.userAgent,
      inputMethod,
      screenOrientation: window.innerHeight > window.innerWidth ? 'portrait' : 'landscape',
      screenDimensions: {
        width: window.innerWidth,
        height: window.innerHeight
      }
    };
  }

  /**
   * Calculates the average pressure from signature stroke data
   * @param signature The signature containing stroke data
   * @returns Average pressure or undefined if no pressure data available
   */
  static calculateAveragePressure(signature: Signature): number | undefined {
    if (!signature.metadata.strokeData) return undefined;

    let totalPressure = 0;
    let pressurePoints = 0;

    signature.metadata.strokeData.forEach(stroke => {
      stroke.points.forEach(point => {
        if (typeof point.pressure === 'number') {
          totalPressure += point.pressure;
          pressurePoints++;
        }
      });
    });

    return pressurePoints > 0 ? totalPressure / pressurePoints : undefined;
  }

  /**
   * Extracts signature dimensions and creates a normalized version
   * @param signature The signature to normalize
   * @returns Object containing normalized dimensions
   */
  static getNormalizedDimensions(signature: Signature): { width: number; height: number } {
    const maxDimension = 1000; // Maximum dimension for normalization
    const aspectRatio = signature.width / signature.height;

    if (signature.width > signature.height) {
      return {
        width: Math.min(signature.width, maxDimension),
        height: Math.min(signature.width, maxDimension) / aspectRatio
      };
    } else {
      return {
        width: Math.min(signature.height, maxDimension) * aspectRatio,
        height: Math.min(signature.height, maxDimension)
      };
    }
  }

  /**
   * Checks if the signature was created within a specific timeframe
   * @param signature The signature to check
   * @param maxAgeMs Maximum age in milliseconds
   * @returns boolean indicating if the signature is within the timeframe
   */
  static isSignatureRecent(signature: Signature, maxAgeMs: number): boolean {
    const signatureAge = Date.now() - signature.createdAt.getTime();
    return signatureAge <= maxAgeMs;
  }

  /**
   * Extracts basic signature information for display or logging
   * @param signature The signature to summarize
   * @returns Object containing basic signature information
   */
  static getSignatureSummary(signature: Signature): {
    id: string;
    userId: string;
    createdAt: Date;
    device: string;
    inputMethod: string;
    label?: string;
  } {
    return {
      id: signature.id,
      userId: signature.userId,
      createdAt: signature.createdAt,
      device: signature.metadata.device,
      inputMethod: signature.metadata.inputMethod,
      label: signature.label
    };
  }
}