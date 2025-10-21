export interface Feedback {
  id: string;
  userId?: string; // Optional - can be anonymous feedback
  email?: string; // Optional contact email
  type: FeedbackType;
  category: FeedbackCategory;
  subject: string;
  message: string;
  rating?: number; // 1-5 star rating
  deviceInfo: DeviceInfo;
  appVersion: string;
  createdAt: Date;
  status: FeedbackStatus;
  metadata?: FeedbackMetadata;
}

export enum FeedbackType {
  BUG_REPORT = 'bug_report',
  FEATURE_REQUEST = 'feature_request',
  GENERAL_FEEDBACK = 'general_feedback',
  SUPPORT_REQUEST = 'support_request',
  COMPLIMENT = 'compliment',
  COMPLAINT = 'complaint'
}

export enum FeedbackCategory {
  USER_INTERFACE = 'user_interface',
  PERFORMANCE = 'performance',
  AUTHENTICATION = 'authentication',
  SIGNATURE_FUNCTIONALITY = 'signature_functionality',
  APPLE_LOGIN = 'apple_login',
  GENERAL = 'general',
  OTHER = 'other'
}

export enum FeedbackStatus {
  SUBMITTED = 'submitted',
  ACKNOWLEDGED = 'acknowledged',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  CLOSED = 'closed'
}

export interface DeviceInfo {
  userAgent: string;
  platform: string;
  screenResolution: string;
  browserName?: string;
  browserVersion?: string;
  isMobile: boolean;
  isTablet: boolean;
}

export interface FeedbackMetadata {
  currentPage?: string;
  sessionId?: string;
  errorLogs?: string[];
  attachments?: string[]; // URLs to uploaded files
  reproductionSteps?: string[];
}

export interface FeedbackRequest {
  type: FeedbackType;
  category: FeedbackCategory;
  subject: string;
  message: string;
  rating?: number;
  email?: string;
  metadata?: Partial<FeedbackMetadata>;
}

export interface FeedbackResponse {
  success: boolean;
  feedbackId?: string;
  message: string;
  error?: string;
}

export class FeedbackBuilder {
  private feedback: Partial<Feedback> = {};

  setType(type: FeedbackType): FeedbackBuilder {
    this.feedback.type = type;
    return this;
  }

  setCategory(category: FeedbackCategory): FeedbackBuilder {
    this.feedback.category = category;
    return this;
  }

  setSubject(subject: string): FeedbackBuilder {
    this.feedback.subject = subject;
    return this;
  }

  setMessage(message: string): FeedbackBuilder {
    this.feedback.message = message;
    return this;
  }

  setRating(rating: number): FeedbackBuilder {
    this.feedback.rating = Math.max(1, Math.min(5, rating)); // Ensure 1-5 range
    return this;
  }

  setEmail(email: string): FeedbackBuilder {
    this.feedback.email = email;
    return this;
  }

  setUserId(userId: string): FeedbackBuilder {
    this.feedback.userId = userId;
    return this;
  }

  setMetadata(metadata: FeedbackMetadata): FeedbackBuilder {
    this.feedback.metadata = metadata;
    return this;
  }

  build(): Feedback {
    if (!this.feedback.type || !this.feedback.category || !this.feedback.subject || !this.feedback.message) {
      throw new Error('Feedback must have type, category, subject, and message');
    }

    const deviceInfo: DeviceInfo = {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      screenResolution: `${screen.width}x${screen.height}`,
      browserName: this.getBrowserName(),
      browserVersion: this.getBrowserVersion(),
      isMobile: /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent),
      isTablet: /iPad|Android(?!.*Mobile)/i.test(navigator.userAgent)
    };

    return {
      id: crypto.randomUUID(),
      type: this.feedback.type,
      category: this.feedback.category,
      subject: this.feedback.subject,
      message: this.feedback.message,
      rating: this.feedback.rating,
      email: this.feedback.email,
      userId: this.feedback.userId,
      deviceInfo,
      appVersion: process.env.REACT_APP_VERSION || '1.0.0',
      createdAt: new Date(),
      status: FeedbackStatus.SUBMITTED,
      metadata: this.feedback.metadata
    };
  }

  private getBrowserName(): string {
    const userAgent = navigator.userAgent;
    if (userAgent.includes('Chrome')) return 'Chrome';
    if (userAgent.includes('Firefox')) return 'Firefox';
    if (userAgent.includes('Safari')) return 'Safari';
    if (userAgent.includes('Edge')) return 'Edge';
    if (userAgent.includes('Opera')) return 'Opera';
    return 'Unknown';
  }

  private getBrowserVersion(): string {
    const userAgent = navigator.userAgent;
    const match = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)\/(\d+)/);
    return match ? match[2] : 'Unknown';
  }
}

// Utility functions for feedback validation
export class FeedbackValidator {
  static validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static validateSubject(subject: string): boolean {
    return subject.trim().length >= 5 && subject.trim().length <= 100;
  }

  static validateMessage(message: string): boolean {
    return message.trim().length >= 10 && message.trim().length <= 2000;
  }

  static validateRating(rating: number): boolean {
    return rating >= 1 && rating <= 5 && Number.isInteger(rating);
  }

  static validateFeedbackRequest(request: FeedbackRequest): string[] {
    const errors: string[] = [];

    if (!Object.values(FeedbackType).includes(request.type)) {
      errors.push('Invalid feedback type');
    }

    if (!Object.values(FeedbackCategory).includes(request.category)) {
      errors.push('Invalid feedback category');
    }

    if (!this.validateSubject(request.subject)) {
      errors.push('Subject must be between 5 and 100 characters');
    }

    if (!this.validateMessage(request.message)) {
      errors.push('Message must be between 10 and 2000 characters');
    }

    if (request.rating && !this.validateRating(request.rating)) {
      errors.push('Rating must be an integer between 1 and 5');
    }

    if (request.email && !this.validateEmail(request.email)) {
      errors.push('Invalid email format');
    }

    return errors;
  }
}