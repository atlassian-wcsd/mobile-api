import { SignatureService } from '../SignatureService';
import { Signature } from '../../models/Signature';

describe('SignatureService', () => {
  let service: SignatureService;

  beforeEach(() => {
    service = new SignatureService();
  });

  describe('createSignature', () => {
    it('creates a new signature with all required fields', () => {
      const imageData = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==';
      const width = 500;
      const height = 200;
      const userId = 'user-123';
      const metadata = {
        device: 'tablet',
        platform: 'iPad Safari',
        pressureData: [0.5, 0.7, 0.9, 0.6],
      };
      const label = 'Contract Signature';

      const signature = service.createSignature(imageData, width, height, userId, metadata, label);

      expect(signature).toMatchObject({
        imageData,
        width,
        height,
        userId,
        metadata,
        label,
      });
      expect(signature.id).toMatch(/^sig_\d+_[a-z0-9]{9}$/);
      expect(signature.createdAt).toBeInstanceOf(Date);
      expect(signature.createdAt.getTime()).toBeCloseTo(Date.now(), -2); // Within 100ms
    });

    it('creates signature without optional label', () => {
      const imageData = 'data:image/png;base64,test';
      const width = 300;
      const height = 150;
      const userId = 'user-456';
      const metadata = {
        device: 'browser',
        platform: 'Chrome',
      };

      const signature = service.createSignature(imageData, width, height, userId, metadata);

      expect(signature.label).toBeUndefined();
      expect(signature.userId).toBe(userId);
    });

    it('generates unique IDs for different signatures', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature1 = service.createSignature(imageData, 500, 200, 'user1', metadata);
      const signature2 = service.createSignature(imageData, 500, 200, 'user2', metadata);

      expect(signature1.id).not.toBe(signature2.id);
    });

    it('stores created signature internally', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature = service.createSignature(imageData, 500, 200, 'user1', metadata);
      const retrieved = service.getSignature(signature.id);

      expect(retrieved).toEqual(signature);
    });
  });

  describe('getSignature', () => {
    it('returns signature when it exists', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature = service.createSignature(imageData, 500, 200, 'user1', metadata);
      const retrieved = service.getSignature(signature.id);

      expect(retrieved).toEqual(signature);
    });

    it('returns null when signature does not exist', () => {
      const retrieved = service.getSignature('non-existent-id');

      expect(retrieved).toBeNull();
    });
  });

  describe('getUserSignatures', () => {
    it('returns all signatures for a specific user', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature1 = service.createSignature(imageData, 500, 200, 'user1', metadata, 'Signature 1');
      const signature2 = service.createSignature(imageData, 400, 150, 'user2', metadata, 'Signature 2');
      const signature3 = service.createSignature(imageData, 600, 250, 'user1', metadata, 'Signature 3');

      const user1Signatures = service.getUserSignatures('user1');
      const user2Signatures = service.getUserSignatures('user2');

      expect(user1Signatures).toHaveLength(2);
      expect(user1Signatures).toContain(signature1);
      expect(user1Signatures).toContain(signature3);

      expect(user2Signatures).toHaveLength(1);
      expect(user2Signatures).toContain(signature2);
    });

    it('returns empty array for user with no signatures', () => {
      const signatures = service.getUserSignatures('non-existent-user');

      expect(signatures).toEqual([]);
    });

    it('returns empty array when no signatures exist', () => {
      const signatures = service.getUserSignatures('any-user');

      expect(signatures).toEqual([]);
    });
  });

  describe('updateSignatureLabel', () => {
    it('updates label of existing signature', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature = service.createSignature(imageData, 500, 200, 'user1', metadata, 'Old Label');
      const updated = service.updateSignatureLabel(signature.id, 'New Label');

      expect(updated).not.toBeNull();
      expect(updated!.label).toBe('New Label');
      expect(updated!.id).toBe(signature.id);

      // Verify the change persisted
      const retrieved = service.getSignature(signature.id);
      expect(retrieved!.label).toBe('New Label');
    });

    it('returns null when signature does not exist', () => {
      const updated = service.updateSignatureLabel('non-existent-id', 'New Label');

      expect(updated).toBeNull();
    });

    it('can update label to empty string', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature = service.createSignature(imageData, 500, 200, 'user1', metadata, 'Original Label');
      const updated = service.updateSignatureLabel(signature.id, '');

      expect(updated!.label).toBe('');
    });
  });

  describe('deleteSignature', () => {
    it('deletes existing signature and returns true', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature = service.createSignature(imageData, 500, 200, 'user1', metadata);
      const deleted = service.deleteSignature(signature.id);

      expect(deleted).toBe(true);

      // Verify signature is gone
      const retrieved = service.getSignature(signature.id);
      expect(retrieved).toBeNull();
    });

    it('returns false when signature does not exist', () => {
      const deleted = service.deleteSignature('non-existent-id');

      expect(deleted).toBe(false);
    });

    it('removes signature from user signatures list', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature1 = service.createSignature(imageData, 500, 200, 'user1', metadata);
      const signature2 = service.createSignature(imageData, 400, 150, 'user1', metadata);

      expect(service.getUserSignatures('user1')).toHaveLength(2);

      service.deleteSignature(signature1.id);

      const remainingSignatures = service.getUserSignatures('user1');
      expect(remainingSignatures).toHaveLength(1);
      expect(remainingSignatures[0]).toEqual(signature2);
    });
  });

  describe('validateSignatureImage', () => {
    it('validates correct PNG image data', () => {
      const validImageData = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==';

      const isValid = service.validateSignatureImage(validImageData);

      expect(isValid).toBe(true);
    });

    it('validates correct JPEG image data', () => {
      const validImageData = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/2wBDAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQH/wAARCAABAAEDASIAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAv/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/8QAFQEBAQAAAAAAAAAAAAAAAAAAAAX/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwA/8A8A';

      const isValid = service.validateSignatureImage(validImageData);

      expect(isValid).toBe(true);
    });

    it('validates correct GIF image data', () => {
      const validImageData = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

      const isValid = service.validateSignatureImage(validImageData);

      expect(isValid).toBe(true);
    });

    it('rejects non-image data URL', () => {
      const invalidImageData = 'data:text/plain;base64,SGVsbG8gV29ybGQ=';

      const isValid = service.validateSignatureImage(invalidImageData);

      expect(isValid).toBe(false);
    });

    it('rejects data without data URL prefix', () => {
      const invalidImageData = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==';

      const isValid = service.validateSignatureImage(invalidImageData);

      expect(isValid).toBe(false);
    });

    it('rejects empty base64 data', () => {
      const invalidImageData = 'data:image/png;base64,';

      const isValid = service.validateSignatureImage(invalidImageData);

      expect(isValid).toBe(false);
    });

    it('rejects malformed data URL', () => {
      const invalidImageData = 'data:image/png';

      const isValid = service.validateSignatureImage(invalidImageData);

      expect(isValid).toBe(false);
    });

    it('handles invalid input gracefully', () => {
      const invalidInputs = [
        '',
        'not-a-data-url',
        'data:',
        null as any,
        undefined as any,
        123 as any,
      ];

      invalidInputs.forEach(input => {
        const isValid = service.validateSignatureImage(input);
        expect(isValid).toBe(false);
      });
    });
  });

  describe('generateSignatureId', () => {
    it('generates unique IDs with correct format', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      const signature1 = service.createSignature(imageData, 500, 200, 'user1', metadata);
      const signature2 = service.createSignature(imageData, 500, 200, 'user1', metadata);

      expect(signature1.id).toMatch(/^sig_\d+_[a-z0-9]{9}$/);
      expect(signature2.id).toMatch(/^sig_\d+_[a-z0-9]{9}$/);
      expect(signature1.id).not.toBe(signature2.id);
    });
  });

  describe('integration tests', () => {
    it('handles complete signature lifecycle', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      // Create signature
      const signature = service.createSignature(imageData, 500, 200, 'user1', metadata, 'Test Signature');
      expect(signature.id).toBeDefined();

      // Retrieve signature
      const retrieved = service.getSignature(signature.id);
      expect(retrieved).toEqual(signature);

      // Update label
      const updated = service.updateSignatureLabel(signature.id, 'Updated Signature');
      expect(updated!.label).toBe('Updated Signature');

      // Check user signatures
      const userSignatures = service.getUserSignatures('user1');
      expect(userSignatures).toHaveLength(1);
      expect(userSignatures[0].label).toBe('Updated Signature');

      // Delete signature
      const deleted = service.deleteSignature(signature.id);
      expect(deleted).toBe(true);

      // Verify deletion
      expect(service.getSignature(signature.id)).toBeNull();
      expect(service.getUserSignatures('user1')).toHaveLength(0);
    });

    it('handles multiple users and signatures', () => {
      const imageData = 'data:image/png;base64,test';
      const metadata = { device: 'browser', platform: 'Chrome' };

      // Create signatures for different users
      const user1Sig1 = service.createSignature(imageData, 500, 200, 'user1', metadata, 'User1 Sig1');
      const user1Sig2 = service.createSignature(imageData, 400, 150, 'user1', metadata, 'User1 Sig2');
      const user2Sig1 = service.createSignature(imageData, 600, 250, 'user2', metadata, 'User2 Sig1');

      // Verify user signatures
      expect(service.getUserSignatures('user1')).toHaveLength(2);
      expect(service.getUserSignatures('user2')).toHaveLength(1);

      // Delete one signature from user1
      service.deleteSignature(user1Sig1.id);

      // Verify counts
      expect(service.getUserSignatures('user1')).toHaveLength(1);
      expect(service.getUserSignatures('user2')).toHaveLength(1);

      // Verify correct signature remains
      const remainingUser1Sigs = service.getUserSignatures('user1');
      expect(remainingUser1Sigs[0]).toEqual(user1Sig2);
    });
  });
});