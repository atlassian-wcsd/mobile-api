import { NotificationService } from '../NotificationService';
import {
  NotificationType,
  NotificationPriority,
  CreateNotificationInput,
} from '../../models/Notification';

describe('NotificationService', () => {
  let service: NotificationService;

  const createInput = (
    overrides: Partial<CreateNotificationInput> = {}
  ): CreateNotificationInput => ({
    userId: 'user-1',
    title: 'Flight Delayed',
    message: 'Your flight AA100 has been delayed by 2 hours.',
    type: NotificationType.DELAY,
    priority: NotificationPriority.HIGH,
    ...overrides,
  });

  beforeEach(() => {
    service = new NotificationService();
  });

  describe('createNotification', () => {
    it('should create a notification with all required fields', () => {
      const input = createInput();
      const notification = service.createNotification(input);

      expect(notification.id).toBeDefined();
      expect(notification.id).toMatch(/^notif_/);
      expect(notification.userId).toBe(input.userId);
      expect(notification.title).toBe(input.title);
      expect(notification.message).toBe(input.message);
      expect(notification.type).toBe(input.type);
      expect(notification.priority).toBe(input.priority);
      expect(notification.isRead).toBe(false);
      expect(notification.createdAt).toBeDefined();
      expect(notification.readAt).toBeNull();
    });

    it('should create a notification with optional metadata', () => {
      const input = createInput({
        metadata: {
          flightNumber: 'AA100',
          previousStatus: 'SCHEDULED',
          newStatus: 'DELAYED',
          gate: 'B12',
          departureTime: '14:30',
          arrivalTime: '18:00',
          bookingReference: 'ABC123',
        },
      });
      const notification = service.createNotification(input);

      expect(notification.metadata).toBeDefined();
      expect(notification.metadata?.flightNumber).toBe('AA100');
      expect(notification.metadata?.previousStatus).toBe('SCHEDULED');
      expect(notification.metadata?.newStatus).toBe('DELAYED');
      expect(notification.metadata?.gate).toBe('B12');
      expect(notification.metadata?.departureTime).toBe('14:30');
      expect(notification.metadata?.arrivalTime).toBe('18:00');
      expect(notification.metadata?.bookingReference).toBe('ABC123');
    });

    it('should assign unique IDs to each notification', () => {
      const n1 = service.createNotification(createInput());
      const n2 = service.createNotification(createInput());

      expect(n1.id).not.toBe(n2.id);
    });

    it('should set createdAt to an ISO date string', () => {
      const notification = service.createNotification(createInput());
      const parsed = new Date(notification.createdAt);
      expect(parsed.toISOString()).toBe(notification.createdAt);
    });
  });

  describe('getNotification', () => {
    it('should return the notification when it exists', () => {
      const created = service.createNotification(createInput());
      const found = service.getNotification(created.id);

      expect(found).not.toBeNull();
      expect(found?.id).toBe(created.id);
      expect(found?.title).toBe(created.title);
    });

    it('should return null when the notification does not exist', () => {
      const found = service.getNotification('nonexistent-id');
      expect(found).toBeNull();
    });
  });

  describe('listNotifications', () => {
    it('should return all notifications for a given user', () => {
      service.createNotification(createInput({ userId: 'user-1' }));
      service.createNotification(createInput({ userId: 'user-1' }));
      service.createNotification(createInput({ userId: 'user-2' }));

      const user1Notifications = service.listNotifications('user-1');
      const user2Notifications = service.listNotifications('user-2');

      expect(user1Notifications).toHaveLength(2);
      expect(user2Notifications).toHaveLength(1);
    });

    it('should return notifications sorted newest first', () => {
      jest.useFakeTimers();

      jest.setSystemTime(new Date('2024-01-01T10:00:00Z'));
      const n1 = service.createNotification(
        createInput({ title: 'First' })
      );

      jest.setSystemTime(new Date('2024-01-01T11:00:00Z'));
      const n2 = service.createNotification(
        createInput({ title: 'Second' })
      );

      jest.setSystemTime(new Date('2024-01-01T12:00:00Z'));
      const n3 = service.createNotification(
        createInput({ title: 'Third' })
      );

      const list = service.listNotifications('user-1');

      // Newest first — the last created should appear first
      expect(list[0].id).toBe(n3.id);
      expect(list[1].id).toBe(n2.id);
      expect(list[2].id).toBe(n1.id);

      jest.useRealTimers();
    });

    it('should return an empty array for a user with no notifications', () => {
      const list = service.listNotifications('unknown-user');
      expect(list).toEqual([]);
    });
  });

  describe('listUnreadNotifications', () => {
    it('should return only unread notifications for the user', () => {
      const n1 = service.createNotification(createInput());
      service.createNotification(createInput());
      service.markAsRead(n1.id);

      const unread = service.listUnreadNotifications('user-1');
      expect(unread).toHaveLength(1);
      expect(unread.every((n) => !n.isRead)).toBe(true);
    });

    it('should return empty array when all notifications are read', () => {
      const n1 = service.createNotification(createInput());
      service.markAsRead(n1.id);

      const unread = service.listUnreadNotifications('user-1');
      expect(unread).toHaveLength(0);
    });
  });

  describe('getUnreadCount', () => {
    it('should return the number of unread notifications for a user', () => {
      service.createNotification(createInput());
      service.createNotification(createInput());
      service.createNotification(createInput({ userId: 'user-2' }));

      expect(service.getUnreadCount('user-1')).toBe(2);
      expect(service.getUnreadCount('user-2')).toBe(1);
    });

    it('should return 0 for a user with no notifications', () => {
      expect(service.getUnreadCount('nobody')).toBe(0);
    });

    it('should decrease after marking a notification as read', () => {
      const n = service.createNotification(createInput());
      expect(service.getUnreadCount('user-1')).toBe(1);

      service.markAsRead(n.id);
      expect(service.getUnreadCount('user-1')).toBe(0);
    });
  });

  describe('markAsRead', () => {
    it('should mark a notification as read and set readAt', () => {
      const created = service.createNotification(createInput());
      const updated = service.markAsRead(created.id);

      expect(updated).not.toBeNull();
      expect(updated?.isRead).toBe(true);
      expect(updated?.readAt).toBeDefined();
      expect(updated?.readAt).not.toBeNull();
    });

    it('should return null for a non-existent notification', () => {
      const result = service.markAsRead('nonexistent');
      expect(result).toBeNull();
    });
  });

  describe('markAsUnread', () => {
    it('should mark a read notification as unread and clear readAt', () => {
      const created = service.createNotification(createInput());
      service.markAsRead(created.id);
      const updated = service.markAsUnread(created.id);

      expect(updated).not.toBeNull();
      expect(updated?.isRead).toBe(false);
      expect(updated?.readAt).toBeNull();
    });

    it('should return null for a non-existent notification', () => {
      const result = service.markAsUnread('nonexistent');
      expect(result).toBeNull();
    });
  });

  describe('markAllAsRead', () => {
    it('should mark all unread notifications for a user as read', () => {
      service.createNotification(createInput());
      service.createNotification(createInput());
      service.createNotification(createInput({ userId: 'user-2' }));

      const count = service.markAllAsRead('user-1');
      expect(count).toBe(2);
      expect(service.getUnreadCount('user-1')).toBe(0);
      // Should not affect other users
      expect(service.getUnreadCount('user-2')).toBe(1);
    });

    it('should return 0 when there are no unread notifications', () => {
      const n = service.createNotification(createInput());
      service.markAsRead(n.id);

      const count = service.markAllAsRead('user-1');
      expect(count).toBe(0);
    });

    it('should return 0 for a user with no notifications', () => {
      const count = service.markAllAsRead('nobody');
      expect(count).toBe(0);
    });
  });

  describe('deleteNotification', () => {
    it('should delete an existing notification and return true', () => {
      const created = service.createNotification(createInput());
      const deleted = service.deleteNotification(created.id);

      expect(deleted).toBe(true);
      expect(service.getNotification(created.id)).toBeNull();
    });

    it('should return false when the notification does not exist', () => {
      const deleted = service.deleteNotification('nonexistent');
      expect(deleted).toBe(false);
    });
  });

  describe('deleteAllNotifications', () => {
    it('should delete all notifications for a user and return the count', () => {
      service.createNotification(createInput());
      service.createNotification(createInput());
      service.createNotification(createInput({ userId: 'user-2' }));

      const count = service.deleteAllNotifications('user-1');
      expect(count).toBe(2);
      expect(service.listNotifications('user-1')).toHaveLength(0);
      // Should not affect other users
      expect(service.listNotifications('user-2')).toHaveLength(1);
    });

    it('should return 0 for a user with no notifications', () => {
      const count = service.deleteAllNotifications('nobody');
      expect(count).toBe(0);
    });
  });

  describe('exportNotificationsAsJson', () => {
    it('should export notifications as a formatted JSON string', () => {
      jest.useFakeTimers();

      jest.setSystemTime(new Date('2024-01-01T10:00:00Z'));
      service.createNotification(createInput({ title: 'Notif A' }));

      jest.setSystemTime(new Date('2024-01-01T11:00:00Z'));
      service.createNotification(createInput({ title: 'Notif B' }));

      const json = service.exportNotificationsAsJson('user-1');
      const parsed = JSON.parse(json);

      expect(Array.isArray(parsed)).toBe(true);
      expect(parsed).toHaveLength(2);
      // Newest first (same ordering as listNotifications)
      expect(parsed[0].title).toBe('Notif B');
      expect(parsed[1].title).toBe('Notif A');

      jest.useRealTimers();
    });

    it('should export an empty array for a user with no notifications', () => {
      const json = service.exportNotificationsAsJson('nobody');
      expect(JSON.parse(json)).toEqual([]);
    });
  });

  describe('importNotificationsFromJson', () => {
    it('should import notifications from a valid JSON string', () => {
      // Create and export notifications
      service.createNotification(createInput({ title: 'Export 1' }));
      service.createNotification(createInput({ title: 'Export 2' }));
      const json = service.exportNotificationsAsJson('user-1');

      // Import into a fresh service
      const newService = new NotificationService();
      const count = newService.importNotificationsFromJson(json);

      expect(count).toBe(2);
      expect(newService.listNotifications('user-1')).toHaveLength(2);
    });

    it('should throw an error for invalid JSON syntax', () => {
      expect(() => {
        service.importNotificationsFromJson('not valid json!!!');
      }).toThrow();
    });

    it('should throw an error when JSON is not an array', () => {
      expect(() => {
        service.importNotificationsFromJson('{"key": "value"}');
      }).toThrow('Invalid JSON: expected an array of notifications');
    });

    it('should skip invalid notification objects in the array', () => {
      const invalidJson = JSON.stringify([
        { id: 'n1', userId: 'u1', title: 't', message: 'm', type: 'GENERAL', priority: 'LOW', isRead: false, createdAt: '2024-01-01T00:00:00.000Z' },
        { invalid: true },
        { id: 'n2', userId: 'u1', title: 't2', message: 'm2', type: 'DELAY', priority: 'HIGH', isRead: false, createdAt: '2024-01-02T00:00:00.000Z' },
      ]);

      const count = service.importNotificationsFromJson(invalidJson);
      expect(count).toBe(2);
    });

    it('should make imported notifications retrievable by ID', () => {
      const json = JSON.stringify([
        {
          id: 'imported-1',
          userId: 'user-1',
          title: 'Imported',
          message: 'Imported notification',
          type: NotificationType.GENERAL,
          priority: NotificationPriority.LOW,
          isRead: false,
          createdAt: '2024-01-01T00:00:00.000Z',
          readAt: null,
        },
      ]);

      service.importNotificationsFromJson(json);
      const found = service.getNotification('imported-1');

      expect(found).not.toBeNull();
      expect(found?.title).toBe('Imported');
    });
  });
});
