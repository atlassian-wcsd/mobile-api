import { Signature } from '../models/Signature';

/**
 * Service class for managing handwriting signatures
 */
export class SignatureService {
  private signatures: Map<string, Signature> = new Map();

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
    metadata: { device: string; platform: string; pressureData?: number[] },
    label?: string
  ): Signature {
    const signature: Signature = {
      id: this.generateSignatureId(),
      imageData,
      width,
      height,
      createdAt: new Date(),
      userId,
      metadata,
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
    return 'sig_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }
}