import {
  Notification,
  NotificationType,
  NotificationPriority,
  CreateNotificationInput,
} from '../models/Notification';

/**
 * Service class for managing in-app notifications.
 * Stores notifications in an in-memory JSON-compatible structure
 * and provides methods to list, create, and mark notifications as read/unread.
 */
export class NotificationService {
  private notifications: Map<string, Notification> = new Map();

  /**
   * Create a new notification
   * @param input - The notification creation input
   * @returns The created notification
   */
  public createNotification(input: CreateNotificationInput): Notification {
    const notification: Notification = {
      id: this.generateNotificationId(),
      userId: input.userId,
      title: input.title,
      message: input.message,
      type: input.type,
      priority: input.priority,
      isRead: false,
      createdAt: new Date().toISOString(),
      readAt: null,
      metadata: input.metadata,
    };

    this.notifications.set(notification.id, notification);
    return notification;
  }

  /**
   * Retrieve a single notification by ID
   * @param notificationId - The ID of the notification
   * @returns The notification if found, null otherwise
   */
  public getNotification(notificationId: string): Notification | null {
    return this.notifications.get(notificationId) ?? null;
  }

  /**
   * List all notifications for a specific user, sorted by creation date (newest first)
   * @param userId - The ID of the user
   * @returns Array of notifications belonging to the user
   */
  public listNotifications(userId: string): Notification[] {
    return Array.from(this.notifications.values())
      .filter((notification) => notification.userId === userId)
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
      );
  }

  /**
   * List only unread notifications for a specific user
   * @param userId - The ID of the user
   * @returns Array of unread notifications belonging to the user
   */
  public listUnreadNotifications(userId: string): Notification[] {
    return this.listNotifications(userId).filter(
      (notification) => !notification.isRead
    );
  }

  /**
   * Get the count of unread notifications for a specific user
   * @param userId - The ID of the user
   * @returns The number of unread notifications
   */
  public getUnreadCount(userId: string): number {
    return Array.from(this.notifications.values()).filter(
      (notification) => notification.userId === userId && !notification.isRead
    ).length;
  }

  /**
   * Mark a notification as read
   * @param notificationId - The ID of the notification to mark as read
   * @returns The updated notification if found, null otherwise
   */
  public markAsRead(notificationId: string): Notification | null {
    const notification = this.notifications.get(notificationId);
    if (!notification) return null;

    notification.isRead = true;
    notification.readAt = new Date().toISOString();
    this.notifications.set(notificationId, notification);
    return notification;
  }

  /**
   * Mark a notification as unread
   * @param notificationId - The ID of the notification to mark as unread
   * @returns The updated notification if found, null otherwise
   */
  public markAsUnread(notificationId: string): Notification | null {
    const notification = this.notifications.get(notificationId);
    if (!notification) return null;

    notification.isRead = false;
    notification.readAt = null;
    this.notifications.set(notificationId, notification);
    return notification;
  }

  /**
   * Mark all notifications as read for a specific user
   * @param userId - The ID of the user
   * @returns The number of notifications marked as read
   */
  public markAllAsRead(userId: string): number {
    const now = new Date().toISOString();
    let count = 0;

    for (const notification of this.notifications.values()) {
      if (notification.userId === userId && !notification.isRead) {
        notification.isRead = true;
        notification.readAt = now;
        this.notifications.set(notification.id, notification);
        count++;
      }
    }

    return count;
  }

  /**
   * Delete a notification by ID
   * @param notificationId - The ID of the notification to delete
   * @returns true if deleted, false if not found
   */
  public deleteNotification(notificationId: string): boolean {
    return this.notifications.delete(notificationId);
  }

  /**
   * Delete all notifications for a specific user
   * @param userId - The ID of the user
   * @returns The number of notifications deleted
   */
  public deleteAllNotifications(userId: string): number {
    let count = 0;

    for (const [id, notification] of this.notifications.entries()) {
      if (notification.userId === userId) {
        this.notifications.delete(id);
        count++;
      }
    }

    return count;
  }

  /**
   * Export all notifications for a user as a JSON string
   * @param userId - The ID of the user
   * @returns JSON string representation of the user's notifications
   */
  public exportNotificationsAsJson(userId: string): string {
    const userNotifications = this.listNotifications(userId);
    return JSON.stringify(userNotifications, null, 2);
  }

  /**
   * Import notifications from a JSON string
   * @param jsonString - JSON string containing an array of notifications
   * @returns The number of notifications imported
   * @throws Error if the JSON is invalid
   */
  public importNotificationsFromJson(jsonString: string): number {
    const parsed: Notification[] = JSON.parse(jsonString);

    if (!Array.isArray(parsed)) {
      throw new Error('Invalid JSON: expected an array of notifications');
    }

    let count = 0;
    for (const notification of parsed) {
      if (this.isValidNotification(notification)) {
        this.notifications.set(notification.id, notification);
        count++;
      }
    }

    return count;
  }

  /**
   * Validate that an object conforms to the Notification interface
   * @param obj - The object to validate
   * @returns true if the object is a valid Notification
   */
  private isValidNotification(obj: unknown): obj is Notification {
    if (typeof obj !== 'object' || obj === null) return false;

    const candidate = obj as Record<string, unknown>;

    return (
      typeof candidate.id === 'string' &&
      typeof candidate.userId === 'string' &&
      typeof candidate.title === 'string' &&
      typeof candidate.message === 'string' &&
      typeof candidate.type === 'string' &&
      typeof candidate.priority === 'string' &&
      typeof candidate.isRead === 'boolean' &&
      typeof candidate.createdAt === 'string'
    );
  }

  /**
   * Generate a unique notification ID
   * @returns A unique string ID
   */
  private generateNotificationId(): string {
    return (
      'notif_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9)
    );
  }
}
