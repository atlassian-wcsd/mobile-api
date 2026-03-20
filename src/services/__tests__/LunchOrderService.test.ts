import { LunchOrderService } from '../LunchOrderService';
import { LunchOrderSubmitRequest, ValidationResult } from '../../models/LunchOrder';

describe('LunchOrderService', () => {
  let service: LunchOrderService;

  beforeEach(() => {
    service = new LunchOrderService();
    // Clear session storage before each test
    sessionStorage.clear();
    localStorage.clear();
  });

  describe('validateLunchOrder', () => {
    describe('Name Validation', () => {
      it('should reject empty name', () => {
        const result = service.validateLunchOrder({
          name: '',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'name')).toBe(true);
      });

      it('should reject name with only whitespace', () => {
        const result = service.validateLunchOrder({
          name: '   ',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'name')).toBe(true);
      });

      it('should reject name shorter than 2 characters', () => {
        const result = service.validateLunchOrder({
          name: 'A',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'name')).toBe(true);
      });

      it('should reject name longer than 100 characters', () => {
        const longName = 'A'.repeat(101);
        const result = service.validateLunchOrder({
          name: longName,
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'name')).toBe(true);
      });

      it('should accept valid name', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'name')).toBe(false);
      });

      it('should accept name with exactly 2 characters', () => {
        const result = service.validateLunchOrder({
          name: 'Jo',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'name')).toBe(false);
      });

      it('should accept name with exactly 100 characters', () => {
        const name100 = 'A'.repeat(100);
        const result = service.validateLunchOrder({
          name: name100,
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'name')).toBe(false);
      });
    });

    describe('Email Validation', () => {
      it('should accept empty email (optional field)', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          email: '',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'email')).toBe(false);
      });

      it('should accept undefined email', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'email')).toBe(false);
      });

      it('should reject invalid email format', () => {
        const invalidEmails = [
          'notanemail',
          'missing@domain',
          '@nodomain.com',
          'spaces in@email.com',
          'user@',
        ];

        invalidEmails.forEach((email) => {
          const result = service.validateLunchOrder({
            name: 'John Doe',
            email,
            menuSelection: 'Pizza',
            quantity: 1,
          });

          expect(result.errors.some((e) => e.field === 'email')).toBe(
            true,
            `Should reject email: ${email}`
          );
        });
      });

      it('should accept valid email formats', () => {
        const validEmails = [
          'user@example.com',
          'john.doe@company.co.uk',
          'test+tag@domain.com',
          'a@b.co',
        ];

        validEmails.forEach((email) => {
          const result = service.validateLunchOrder({
            name: 'John Doe',
            email,
            menuSelection: 'Pizza',
            quantity: 1,
          });

          expect(result.errors.some((e) => e.field === 'email')).toBe(
            false,
            `Should accept email: ${email}`
          );
        });
      });

      it('should reject email longer than 254 characters', () => {
        const longEmail = 'a'.repeat(250) + '@b.co';
        const result = service.validateLunchOrder({
          name: 'John Doe',
          email: longEmail,
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'email')).toBe(true);
      });
    });

    describe('Menu Selection Validation', () => {
      it('should reject empty menu selection', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: '',
          quantity: 1,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'menuSelection')).toBe(
          true
        );
      });

      it('should reject menu selection with only whitespace', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: '   ',
          quantity: 1,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'menuSelection')).toBe(
          true
        );
      });

      it('should reject menu selection longer than 200 characters', () => {
        const longMenu = 'A'.repeat(201);
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: longMenu,
          quantity: 1,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'menuSelection')).toBe(
          true
        );
      });

      it('should accept valid menu selection', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Grilled Chicken Sandwich',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'menuSelection')).toBe(
          false
        );
      });
    });

    describe('Quantity Validation', () => {
      it('should reject missing quantity', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: undefined as any,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'quantity')).toBe(true);
      });

      it('should reject null quantity', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: null as any,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'quantity')).toBe(true);
      });

      it('should reject zero quantity', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 0,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'quantity')).toBe(true);
      });

      it('should reject negative quantity', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: -5,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'quantity')).toBe(true);
      });

      it('should reject decimal quantity', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1.5,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'quantity')).toBe(true);
      });

      it('should reject quantity exceeding maximum (1000)', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1001,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'quantity')).toBe(true);
      });

      it('should accept valid quantity', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 5,
        });

        expect(result.errors.some((e) => e.field === 'quantity')).toBe(false);
      });

      it('should accept quantity of 1 (minimum)', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'quantity')).toBe(false);
      });

      it('should accept quantity of 1000 (maximum)', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1000,
        });

        expect(result.errors.some((e) => e.field === 'quantity')).toBe(false);
      });
    });

    describe('Special Instructions Validation', () => {
      it('should accept empty special instructions (optional)', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
          specialInstructions: '',
        });

        expect(result.errors.some((e) => e.field === 'specialInstructions')).toBe(
          false
        );
      });

      it('should accept undefined special instructions', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
        });

        expect(result.errors.some((e) => e.field === 'specialInstructions')).toBe(
          false
        );
      });

      it('should reject special instructions longer than 1000 characters', () => {
        const longInstructions = 'A'.repeat(1001);
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
          specialInstructions: longInstructions,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'specialInstructions')).toBe(
          true
        );
      });

      it('should accept valid special instructions', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
          specialInstructions: 'No onions, extra cheese',
        });

        expect(result.errors.some((e) => e.field === 'specialInstructions')).toBe(
          false
        );
      });

      it('should accept special instructions with exactly 1000 characters', () => {
        const instructions1000 = 'A'.repeat(1000);
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
          specialInstructions: instructions1000,
        });

        expect(result.errors.some((e) => e.field === 'specialInstructions')).toBe(
          false
        );
      });
    });

    describe('Delivery Location Validation', () => {
      it('should accept empty delivery location (optional)', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
          deliveryLocation: '',
        });

        expect(result.errors.some((e) => e.field === 'deliveryLocation')).toBe(
          false
        );
      });

      it('should reject delivery location longer than 500 characters', () => {
        const longLocation = 'A'.repeat(501);
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
          deliveryLocation: longLocation,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.some((e) => e.field === 'deliveryLocation')).toBe(
          true
        );
      });

      it('should accept valid delivery location', () => {
        const result = service.validateLunchOrder({
          name: 'John Doe',
          menuSelection: 'Pizza',
          quantity: 1,
          deliveryLocation: 'Building A, Floor 3, Room 301',
        });

        expect(result.errors.some((e) => e.field === 'deliveryLocation')).toBe(
          false
        );
      });
    });

    describe('Complete Form Validation', () => {
      it('should validate all fields correctly together', () => {
        const validOrder: LunchOrderSubmitRequest = {
          name: 'John Doe',
          email: 'john@example.com',
          menuSelection: 'Pizza',
          quantity: 2,
          specialInstructions: 'Extra cheese',
          deliveryLocation: 'Building A',
          notificationsEnabled: true,
        };

        const result = service.validateLunchOrder(validOrder);
        expect(result.isValid).toBe(true);
        expect(result.errors.length).toBe(0);
      });

      it('should report all errors when multiple fields are invalid', () => {
        const result = service.validateLunchOrder({
          name: 'A', // Too short
          email: 'invalid-email', // Invalid
          menuSelection: '', // Empty
          quantity: 0, // Invalid
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(1);
        expect(result.errors.map((e) => e.field)).toContain('name');
        expect(result.errors.map((e) => e.field)).toContain('email');
        expect(result.errors.map((e) => e.field)).toContain('menuSelection');
        expect(result.errors.map((e) => e.field)).toContain('quantity');
      });

      it('should validate minimal required fields', () => {
        const minimalOrder: LunchOrderSubmitRequest = {
          name: 'Jane Smith',
          menuSelection: 'Salad',
          quantity: 1,
          notificationsEnabled: false,
        };

        const result = service.validateLunchOrder(minimalOrder);
        expect(result.isValid).toBe(true);
      });
    });

    describe('Edge Cases', () => {
      it('should handle null values gracefully', () => {
        const result = service.validateLunchOrder({
          name: null as any,
          menuSelection: null as any,
          quantity: null as any,
        });

        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });

      it('should trim whitespace from name and menuSelection', () => {
        const result = service.validateLunchOrder({
          name: '  John Doe  ',
          menuSelection: '  Pizza  ',
          quantity: 1,
        });

        // The service should validate but the component should handle trimming
        expect(result.isValid).toBe(true);
      });

      it('should handle special characters in fields', () => {
        const result = service.validateLunchOrder({
          name: "O'Brien",
          menuSelection: "Fish & Chips",
          quantity: 1,
          specialInstructions: "No nuts (tree nuts & peanuts)",
          deliveryLocation: "Building #1, Floor 2-3",
        });

        expect(result.isValid).toBe(true);
      });
    });
  });
});
