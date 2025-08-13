export interface Feedback {
  id: string;
  userId?: string;
  email?: string;
  rating: number; // 1-5 star rating
  category: FeedbackCategory;
  subject: string;
  message: string;
  attachments?: string[]; // URLs to uploaded files
  deviceInfo?: DeviceInfo;
  createdAt: Date;
  status: FeedbackStatus;
  response?: string;
  respondedAt?: Date;
  respondedBy?: string;
}

export enum FeedbackCategory {
  BUG_REPORT = 'bug_report',
  FEATURE_REQUEST = 'feature_request',
  GENERAL_FEEDBACK = 'general_feedback',
  SUPPORT_REQUEST = 'support_request',
  PERFORMANCE_ISSUE = 'performance_issue',
  UI_UX_FEEDBACK = 'ui_ux_feedback'
}

export enum FeedbackStatus {
  SUBMITTED = 'submitted',
  IN_REVIEW = 'in_review',
  RESOLVED = 'resolved',
  CLOSED = 'closed'
}

export interface DeviceInfo {
  userAgent: string;
  platform: string;
  screenResolution: string;
  viewport: string;
  timestamp: Date;
}

export interface FeedbackSubmissionRequest {
  rating: number;
  category: FeedbackCategory;
  subject: string;
  message: string;
  email?: string;
  attachments?: File[];
}

export interface FeedbackSubmissionResponse {
  success: boolean;
  feedbackId?: string;
  error?: string;
  message?: string;
}

export class FeedbackBuilder {
  private feedback: Partial<Feedback> = {};

  setUserId(userId: string): FeedbackBuilder {
    this.feedback.userId = userId;
    return this;
  }

  setEmail(email: string): FeedbackBuilder {
    this.feedback.email = email;
    return this;
  }

  setRating(rating: number): FeedbackBuilder {
    if (rating < 1 || rating > 5) {
      throw new Error('Rating must be between 1 and 5');
    }
    this.feedback.rating = rating;
    return this;
  }

  setCategory(category: FeedbackCategory): FeedbackBuilder {
    this.feedback.category = category;
    return this;
  }

  setSubject(subject: string): FeedbackBuilder {
    this.feedback.subject = subject.trim();
    return this;
  }

  setMessage(message: string): FeedbackBuilder {
    this.feedback.message = message.trim();
    return this;
  }

  setAttachments(attachments: string[]): FeedbackBuilder {
    this.feedback.attachments = attachments;
    return this;
  }

  setDeviceInfo(deviceInfo: DeviceInfo): FeedbackBuilder {
    this.feedback.deviceInfo = deviceInfo;
    return this;
  }

  build(): Feedback {
    const now = new Date();
    
    if (!this.feedback.rating || !this.feedback.category || 
        !this.feedback.subject || !this.feedback.message) {
      throw new Error('Feedback must have rating, category, subject, and message');
    }

    return {
      id: crypto.randomUUID(),
      userId: this.feedback.userId,
      email: this.feedback.email,
      rating: this.feedback.rating,
      category: this.feedback.category,
      subject: this.feedback.subject,
      message: this.feedback.message,
      attachments: this.feedback.attachments || [],
      deviceInfo: this.feedback.deviceInfo || {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        screenResolution: `${screen.width}x${screen.height}`,
        viewport: `${window.innerWidth}x${window.innerHeight}`,
        timestamp: now
      },
      createdAt: now,
      status: FeedbackStatus.SUBMITTED
    };
  }
}

export class FeedbackValidator {
  static validateRating(rating: number): boolean {
    return rating >= 1 && rating <= 5 && Number.isInteger(rating);
  }

  static validateSubject(subject: string): boolean {
    return subject.trim().length >= 3 && subject.trim().length <= 100;
  }

  static validateMessage(message: string): boolean {
    return message.trim().length >= 10 && message.trim().length <= 2000;
  }

  static validateEmail(email: string): boolean {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  static validateFeedback(feedback: FeedbackSubmissionRequest): string[] {
    const errors: string[] = [];

    if (!this.validateRating(feedback.rating)) {
      errors.push('Rating must be between 1 and 5');
    }

    if (!feedback.category) {
      errors.push('Category is required');
    }

    if (!this.validateSubject(feedback.subject)) {
      errors.push('Subject must be between 3 and 100 characters');
    }

    if (!this.validateMessage(feedback.message)) {
      errors.push('Message must be between 10 and 2000 characters');
    }

    if (feedback.email && !this.validateEmail(feedback.email)) {
      errors.push('Please provide a valid email address');
    }

    return errors;
  }
}