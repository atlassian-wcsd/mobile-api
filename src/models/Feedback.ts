export interface Feedback {
  id: string;
  userId?: string;
  rating: number; // 1-5 star rating
  feedbackText: string;
  category: FeedbackCategory;
  contactEmail?: string;
  deviceInfo?: DeviceInfo;
  createdAt: Date;
  status: FeedbackStatus;
  metadata?: FeedbackMetadata;
}

export enum FeedbackCategory {
  BUG_REPORT = 'bug_report',
  FEATURE_REQUEST = 'feature_request',
  GENERAL_FEEDBACK = 'general_feedback',
  USER_EXPERIENCE = 'user_experience',
  PERFORMANCE = 'performance',
  OTHER = 'other'
}

export enum FeedbackStatus {
  SUBMITTED = 'submitted',
  REVIEWED = 'reviewed',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  CLOSED = 'closed'
}

export interface DeviceInfo {
  userAgent: string;
  platform: string;
  screenResolution: string;
  viewport: string;
  language: string;
  timezone: string;
}

export interface FeedbackMetadata {
  appVersion?: string;
  currentPage?: string;
  sessionId?: string;
  referrer?: string;
}

export interface FeedbackSubmissionRequest {
  rating: number;
  feedbackText: string;
  category: FeedbackCategory;
  contactEmail?: string;
  deviceInfo?: DeviceInfo;
  metadata?: FeedbackMetadata;
}

export interface FeedbackSubmissionResponse {
  success: boolean;
  feedbackId?: string;
  message: string;
  error?: string;
}

export class FeedbackBuilder {
  private feedback: Partial<Feedback> = {};

  constructor() {
    this.feedback.id = crypto.randomUUID();
    this.feedback.createdAt = new Date();
    this.feedback.status = FeedbackStatus.SUBMITTED;
  }

  setUserId(userId: string): FeedbackBuilder {
    this.feedback.userId = userId;
    return this;
  }

  setRating(rating: number): FeedbackBuilder {
    if (rating < 1 || rating > 5) {
      throw new Error('Rating must be between 1 and 5');
    }
    this.feedback.rating = rating;
    return this;
  }

  setFeedbackText(text: string): FeedbackBuilder {
    if (!text || text.trim().length === 0) {
      throw new Error('Feedback text is required');
    }
    if (text.length > 2000) {
      throw new Error('Feedback text must be less than 2000 characters');
    }
    this.feedback.feedbackText = text.trim();
    return this;
  }

  setCategory(category: FeedbackCategory): FeedbackBuilder {
    this.feedback.category = category;
    return this;
  }

  setContactEmail(email: string): FeedbackBuilder {
    if (email && !this.isValidEmail(email)) {
      throw new Error('Invalid email format');
    }
    this.feedback.contactEmail = email;
    return this;
  }

  setDeviceInfo(deviceInfo: DeviceInfo): FeedbackBuilder {
    this.feedback.deviceInfo = deviceInfo;
    return this;
  }

  setMetadata(metadata: FeedbackMetadata): FeedbackBuilder {
    this.feedback.metadata = metadata;
    return this;
  }

  build(): Feedback {
    if (!this.feedback.rating || !this.feedback.feedbackText || !this.feedback.category) {
      throw new Error('Rating, feedback text, and category are required');
    }
    return this.feedback as Feedback;
  }

  private isValidEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }
}

export class FeedbackUtils {
  static getDeviceInfo(): DeviceInfo {
    return {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      screenResolution: `${screen.width}x${screen.height}`,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
  }

  static getMetadata(): FeedbackMetadata {
    return {
      appVersion: process.env.REACT_APP_VERSION || '1.0.0',
      currentPage: window.location.pathname,
      sessionId: sessionStorage.getItem('sessionId') || 'unknown',
      referrer: document.referrer || 'direct'
    };
  }

  static getCategoryDisplayName(category: FeedbackCategory): string {
    switch (category) {
      case FeedbackCategory.BUG_REPORT:
        return 'Bug Report';
      case FeedbackCategory.FEATURE_REQUEST:
        return 'Feature Request';
      case FeedbackCategory.GENERAL_FEEDBACK:
        return 'General Feedback';
      case FeedbackCategory.USER_EXPERIENCE:
        return 'User Experience';
      case FeedbackCategory.PERFORMANCE:
        return 'Performance';
      case FeedbackCategory.OTHER:
        return 'Other';
      default:
        return 'Unknown';
    }
  }

  static validateFeedbackText(text: string): string | null {
    if (!text || text.trim().length === 0) {
      return 'Feedback text is required';
    }
    if (text.length < 10) {
      return 'Feedback text must be at least 10 characters';
    }
    if (text.length > 2000) {
      return 'Feedback text must be less than 2000 characters';
    }
    return null;
  }

  static validateRating(rating: number): string | null {
    if (!rating || rating < 1 || rating > 5) {
      return 'Please provide a rating between 1 and 5 stars';
    }
    return null;
  }

  static validateEmail(email: string): string | null {
    if (!email) return null; // Email is optional
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return 'Please enter a valid email address';
    }
    return null;
  }
}