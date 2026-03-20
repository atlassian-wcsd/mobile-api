/**
 * Interface representing a lunch order
 */
export interface LunchOrder {
  /**
   * Unique identifier for the order
   */
  id: string;

  /**
   * User ID who placed the order
   */
  userId: string;

  /**
   * Full name of the person placing the order (required)
   */
  name: string;

  /**
   * Email address for the order (optional but validated if provided)
   */
  email?: string;

  /**
   * Selected menu item (required)
   */
  menuSelection: string;

  /**
   * Dietary restrictions or special instructions (optional)
   */
  specialInstructions?: string;

  /**
   * Quantity of items ordered (required, minimum 1)
   */
  quantity: number;

  /**
   * Delivery location or address (optional)
   */
  deliveryLocation?: string;

  /**
   * Order timestamp
   */
  createdAt: Date;

  /**
   * Status of the order (pending, confirmed, delivered, cancelled)
   */
  status: 'pending' | 'confirmed' | 'delivered' | 'cancelled';

  /**
   * Order total price (optional)
   */
  totalPrice?: number;

  /**
   * Whether user opted in for notifications
   */
  notificationsEnabled: boolean;

  /**
   * Admin notes (internal use)
   */
  adminNotes?: string;

  /**
   * Last updated timestamp
   */
  updatedAt?: Date;
}

/**
 * Request payload for submitting a lunch order
 */
export interface LunchOrderSubmitRequest {
  name: string;
  email?: string;
  menuSelection: string;
  specialInstructions?: string;
  quantity: number;
  deliveryLocation?: string;
  notificationsEnabled: boolean;
}

/**
 * Response after submitting a lunch order
 */
export interface LunchOrderSubmitResponse {
  success: boolean;
  orderId?: string;
  message: string;
  error?: string;
  validationErrors?: Record<string, string>;
}

/**
 * Validation error details for lunch order input
 */
export interface ValidationError {
  field: string;
  message: string;
  value?: any;
}

/**
 * Result of validation check
 */
export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
}

/**
 * Available menu items for lunch orders
 */
export interface MenuItem {
  id: string;
  name: string;
  description: string;
  price: number;
  isAvailable: boolean;
}
