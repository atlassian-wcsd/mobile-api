/**
 * Enum representing the type of notification
 */
export enum NotificationType {
  FLIGHT_STATUS = 'FLIGHT_STATUS',
  GATE_CHANGE = 'GATE_CHANGE',
  BOOKING_UPDATE = 'BOOKING_UPDATE',
  DELAY = 'DELAY',
  CANCELLATION = 'CANCELLATION',
  GENERAL = 'GENERAL',
}

/**
 * Enum representing the priority level of a notification
 */
export enum NotificationPriority {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  URGENT = 'URGENT',
}

/**
 * Interface representing an in-app notification for travel events
 */
export interface Notification {
  /**
   * Unique identifier for the notification
   */
  id: string;

  /**
   * ID of the user this notification belongs to
   */
  userId: string;

  /**
   * Title of the notification (short summary)
   */
  title: string;

  /**
   * Detailed message body of the notification
   */
  message: string;

  /**
   * Type of notification
   */
  type: NotificationType;

  /**
   * Priority level of the notification
   */
  priority: NotificationPriority;

  /**
   * Whether the notification has been read by the user
   */
  isRead: boolean;

  /**
   * Timestamp when the notification was created
   */
  createdAt: string;

  /**
   * Timestamp when the notification was read (null if unread)
   */
  readAt: string | null;

  /**
   * Optional metadata with additional context about the notification
   */
  metadata?: NotificationMetadata;
}

/**
 * Interface for notification metadata providing additional context
 */
export interface NotificationMetadata {
  /**
   * Flight number associated with the notification
   */
  flightNumber?: string;

  /**
   * Previous status before the change (for status-change notifications)
   */
  previousStatus?: string;

  /**
   * New status after the change (for status-change notifications)
   */
  newStatus?: string;

  /**
   * Gate information (for gate-change notifications)
   */
  gate?: string;

  /**
   * Departure time information
   */
  departureTime?: string;

  /**
   * Arrival time information
   */
  arrivalTime?: string;

  /**
   * Booking reference associated with the notification
   */
  bookingReference?: string;
}

/**
 * Interface for creating a new notification (omits auto-generated fields)
 */
export interface CreateNotificationInput {
  userId: string;
  title: string;
  message: string;
  type: NotificationType;
  priority: NotificationPriority;
  metadata?: NotificationMetadata;
}
