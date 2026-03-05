import React, { useState, useCallback, useMemo } from 'react';
import { Notification, NotificationType, NotificationPriority } from '../models/Notification';
import { NotificationService } from '../services/NotificationService';

interface NotificationFeedProps {
  notificationService: NotificationService;
  userId: string;
  className?: string;
}

/**
 * Get a display-friendly label for the notification type
 */
const getTypeLabel = (type: NotificationType): string => {
  const typeLabels: Record<NotificationType, string> = {
    [NotificationType.FLIGHT_STATUS]: '✈️ Flight Status',
    [NotificationType.GATE_CHANGE]: '🚪 Gate Change',
    [NotificationType.BOOKING_UPDATE]: '📋 Booking Update',
    [NotificationType.DELAY]: '⏰ Delay',
    [NotificationType.CANCELLATION]: '❌ Cancellation',
    [NotificationType.GENERAL]: '📢 General',
  };
  return typeLabels[type] ?? type;
};

/**
 * Get a CSS-friendly priority class name
 */
const getPriorityClass = (priority: NotificationPriority): string => {
  const priorityClasses: Record<NotificationPriority, string> = {
    [NotificationPriority.LOW]: 'notification-priority-low',
    [NotificationPriority.MEDIUM]: 'notification-priority-medium',
    [NotificationPriority.HIGH]: 'notification-priority-high',
    [NotificationPriority.URGENT]: 'notification-priority-urgent',
  };
  return priorityClasses[priority] ?? '';
};

/**
 * Get the background color for a priority level
 */
const getPriorityColor = (priority: NotificationPriority): string => {
  const priorityColors: Record<NotificationPriority, string> = {
    [NotificationPriority.LOW]: '#e8f5e9',
    [NotificationPriority.MEDIUM]: '#fff3e0',
    [NotificationPriority.HIGH]: '#fce4ec',
    [NotificationPriority.URGENT]: '#ffcdd2',
  };
  return priorityColors[priority] ?? '#ffffff';
};

/**
 * Format a date string into a human-readable relative time
 */
const formatRelativeTime = (dateString: string): string => {
  const now = new Date();
  const date = new Date(dateString);
  const diffMs = now.getTime() - date.getTime();
  const diffSeconds = Math.floor(diffMs / 1000);
  const diffMinutes = Math.floor(diffSeconds / 60);
  const diffHours = Math.floor(diffMinutes / 60);
  const diffDays = Math.floor(diffHours / 24);

  if (diffSeconds < 60) return 'Just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};

/**
 * NotificationFeed component displays a panel of in-app notifications
 * with an unread indicator badge and the ability to mark items as read/unread.
 */
export const NotificationFeed: React.FC<NotificationFeedProps> = ({
  notificationService,
  userId,
  className,
}) => {
  const [isPanelOpen, setIsPanelOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const forceRefresh = useCallback(() => {
    setRefreshKey((prev) => prev + 1);
  }, []);

  const notifications = useMemo(
    () => notificationService.listNotifications(userId),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [notificationService, userId, refreshKey]
  );

  const unreadCount = useMemo(
    () => notificationService.getUnreadCount(userId),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [notificationService, userId, refreshKey]
  );

  const handleTogglePanel = useCallback(() => {
    setIsPanelOpen((prev) => !prev);
  }, []);

  const handleMarkAsRead = useCallback(
    (notificationId: string) => {
      notificationService.markAsRead(notificationId);
      forceRefresh();
    },
    [notificationService, forceRefresh]
  );

  const handleMarkAsUnread = useCallback(
    (notificationId: string) => {
      notificationService.markAsUnread(notificationId);
      forceRefresh();
    },
    [notificationService, forceRefresh]
  );

  const handleMarkAllAsRead = useCallback(() => {
    notificationService.markAllAsRead(userId);
    forceRefresh();
  }, [notificationService, userId, forceRefresh]);

  const handleDelete = useCallback(
    (notificationId: string) => {
      notificationService.deleteNotification(notificationId);
      forceRefresh();
    },
    [notificationService, forceRefresh]
  );

  return (
    <div className={`notification-feed ${className ?? ''}`} style={styles.container}>
      {/* Bell icon with unread badge */}
      <button
        onClick={handleTogglePanel}
        style={styles.bellButton}
        aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ''}`}
      >
        <span style={styles.bellIcon}>🔔</span>
        {unreadCount > 0 && (
          <span
            className="notification-unread-badge"
            style={styles.unreadBadge}
            data-testid="unread-badge"
          >
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Notification panel */}
      {isPanelOpen && (
        <div
          className="notification-panel"
          style={styles.panel}
          role="region"
          aria-label="Notifications"
        >
          {/* Panel header */}
          <div style={styles.panelHeader}>
            <h3 style={styles.panelTitle}>Notifications</h3>
            {unreadCount > 0 && (
              <button
                onClick={handleMarkAllAsRead}
                style={styles.markAllReadButton}
              >
                Mark all as read
              </button>
            )}
          </div>

          {/* Notification list */}
          <div style={styles.notificationList}>
            {notifications.length === 0 ? (
              <div style={styles.emptyState}>
                <p>No notifications yet</p>
              </div>
            ) : (
              notifications.map((notification) => (
                <NotificationItem
                  key={notification.id}
                  notification={notification}
                  onMarkAsRead={handleMarkAsRead}
                  onMarkAsUnread={handleMarkAsUnread}
                  onDelete={handleDelete}
                />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};

/**
 * Props for a single notification item
 */
interface NotificationItemProps {
  notification: Notification;
  onMarkAsRead: (id: string) => void;
  onMarkAsUnread: (id: string) => void;
  onDelete: (id: string) => void;
}

/**
 * Individual notification item component
 */
const NotificationItem: React.FC<NotificationItemProps> = ({
  notification,
  onMarkAsRead,
  onMarkAsUnread,
  onDelete,
}) => {
  const itemStyle: React.CSSProperties = {
    ...styles.notificationItem,
    backgroundColor: notification.isRead ? '#f9f9f9' : getPriorityColor(notification.priority),
    borderLeft: `4px solid ${notification.isRead ? '#ccc' : getAccentColor(notification.priority)}`,
    opacity: notification.isRead ? 0.8 : 1,
  };

  return (
    <div
      className={`notification-item ${getPriorityClass(notification.priority)}`}
      style={itemStyle}
      role="article"
      aria-label={notification.title}
    >
      <div style={styles.itemHeader}>
        <span style={styles.typeLabel}>{getTypeLabel(notification.type)}</span>
        <span style={styles.timestamp}>
          {formatRelativeTime(notification.createdAt)}
        </span>
      </div>

      <h4 style={styles.itemTitle}>
        {!notification.isRead && (
          <span style={styles.unreadDot} aria-label="Unread">
            ●
          </span>
        )}
        {notification.title}
      </h4>

      <p style={styles.itemMessage}>{notification.message}</p>

      {notification.metadata?.flightNumber && (
        <div style={styles.metadataRow}>
          <span style={styles.metadataLabel}>Flight:</span>
          <span>{notification.metadata.flightNumber}</span>
          {notification.metadata.gate && (
            <>
              <span style={styles.metadataLabel}>Gate:</span>
              <span>{notification.metadata.gate}</span>
            </>
          )}
        </div>
      )}

      <div style={styles.itemActions}>
        {notification.isRead ? (
          <button
            onClick={() => onMarkAsUnread(notification.id)}
            style={styles.actionButton}
          >
            Mark as unread
          </button>
        ) : (
          <button
            onClick={() => onMarkAsRead(notification.id)}
            style={styles.actionButton}
          >
            Mark as read
          </button>
        )}
        <button
          onClick={() => onDelete(notification.id)}
          style={{ ...styles.actionButton, color: '#d32f2f' }}
        >
          Delete
        </button>
      </div>
    </div>
  );
};

/**
 * Get the accent color for the left border based on priority
 */
const getAccentColor = (priority: NotificationPriority): string => {
  const accentColors: Record<NotificationPriority, string> = {
    [NotificationPriority.LOW]: '#4caf50',
    [NotificationPriority.MEDIUM]: '#ff9800',
    [NotificationPriority.HIGH]: '#f44336',
    [NotificationPriority.URGENT]: '#b71c1c',
  };
  return accentColors[priority] ?? '#ccc';
};

/**
 * Inline styles for the notification feed
 */
const styles: Record<string, React.CSSProperties> = {
  container: {
    position: 'relative',
    display: 'inline-block',
  },
  bellButton: {
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    position: 'relative',
    padding: '8px',
    fontSize: '24px',
  },
  bellIcon: {
    fontSize: '24px',
  },
  unreadBadge: {
    position: 'absolute',
    top: '2px',
    right: '2px',
    backgroundColor: '#f44336',
    color: '#ffffff',
    borderRadius: '50%',
    minWidth: '18px',
    height: '18px',
    fontSize: '11px',
    fontWeight: 'bold',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '0 4px',
  },
  panel: {
    position: 'absolute',
    top: '100%',
    right: '0',
    width: '380px',
    maxHeight: '500px',
    backgroundColor: '#ffffff',
    border: '1px solid #e0e0e0',
    borderRadius: '8px',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
    zIndex: 1000,
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column',
  },
  panelHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '12px 16px',
    borderBottom: '1px solid #e0e0e0',
    backgroundColor: '#fafafa',
  },
  panelTitle: {
    margin: 0,
    fontSize: '16px',
    fontWeight: 600,
  },
  markAllReadButton: {
    background: 'none',
    border: 'none',
    color: '#1976d2',
    cursor: 'pointer',
    fontSize: '13px',
    padding: '4px 8px',
  },
  notificationList: {
    overflowY: 'auto',
    flex: 1,
  },
  emptyState: {
    padding: '32px 16px',
    textAlign: 'center',
    color: '#999',
  },
  notificationItem: {
    padding: '12px 16px',
    borderBottom: '1px solid #f0f0f0',
    cursor: 'default',
    transition: 'background-color 0.2s',
  },
  itemHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '4px',
  },
  typeLabel: {
    fontSize: '12px',
    color: '#666',
  },
  timestamp: {
    fontSize: '12px',
    color: '#999',
  },
  itemTitle: {
    margin: '0 0 4px 0',
    fontSize: '14px',
    fontWeight: 600,
  },
  unreadDot: {
    color: '#1976d2',
    marginRight: '6px',
    fontSize: '10px',
  },
  itemMessage: {
    margin: '0 0 8px 0',
    fontSize: '13px',
    color: '#555',
    lineHeight: '1.4',
  },
  metadataRow: {
    display: 'flex',
    gap: '8px',
    fontSize: '12px',
    color: '#777',
    marginBottom: '8px',
  },
  metadataLabel: {
    fontWeight: 600,
  },
  itemActions: {
    display: 'flex',
    gap: '8px',
  },
  actionButton: {
    background: 'none',
    border: 'none',
    color: '#1976d2',
    cursor: 'pointer',
    fontSize: '12px',
    padding: '2px 4px',
  },
};

export default NotificationFeed;
