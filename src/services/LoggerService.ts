import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class LoggerService {
  private logPrefix = '[MFIRST Registration]';

  constructor() {}

  /**
   * Log registration attempt
   * @param username The username attempting registration
   * @param success Whether the registration was successful
   * @param details Additional details about the registration attempt
   */
  logRegistrationAttempt(username: string, success: boolean, details?: string) {
    const timestamp = new Date().toISOString();
    const status = success ? 'SUCCESS' : 'FAILURE';
    const message = `${this.logPrefix} [${timestamp}] Registration ${status} - User: ${username}${details ? ` - Details: ${details}` : ''}`;
    
    if (success) {
      console.log(message);
    } else {
      console.warn(message);
    }

    // TODO: Implement persistent logging to backend service
  }

  /**
   * Log email verification events
   * @param username The username being verified
   * @param success Whether the verification was successful
   * @param details Additional details about the verification
   */
  logEmailVerification(username: string, success: boolean, details?: string) {
    const timestamp = new Date().toISOString();
    const status = success ? 'SUCCESS' : 'FAILURE';
    const message = `${this.logPrefix} [${timestamp}] Email Verification ${status} - User: ${username}${details ? ` - Details: ${details}` : ''}`;
    
    if (success) {
      console.log(message);
    } else {
      console.warn(message);
    }

    // TODO: Implement persistent logging to backend service
  }

  /**
   * Log password reset attempts
   * @param username The username requesting password reset
   * @param success Whether the password reset was successful
   * @param details Additional details about the password reset
   */
  logPasswordReset(username: string, success: boolean, details?: string) {
    const timestamp = new Date().toISOString();
    const status = success ? 'SUCCESS' : 'FAILURE';
    const message = `${this.logPrefix} [${timestamp}] Password Reset ${status} - User: ${username}${details ? ` - Details: ${details}` : ''}`;
    
    if (success) {
      console.log(message);
    } else {
      console.warn(message);
    }

    // TODO: Implement persistent logging to backend service
  }

  /**
   * Log profile update events
   * @param username The username updating their profile
   * @param success Whether the update was successful
   * @param details Additional details about the update
   */
  logProfileUpdate(username: string, success: boolean, details?: string) {
    const timestamp = new Date().toISOString();
    const status = success ? 'SUCCESS' : 'FAILURE';
    const message = `${this.logPrefix} [${timestamp}] Profile Update ${status} - User: ${username}${details ? ` - Details: ${details}` : ''}`;
    
    if (success) {
      console.log(message);
    } else {
      console.warn(message);
    }

    // TODO: Implement persistent logging to backend service
  }

  /**
   * Log security events (CAPTCHA, suspicious activity, etc.)
   * @param eventType Type of security event
   * @param details Details about the security event
   */
  logSecurityEvent(eventType: string, details: string) {
    const timestamp = new Date().toISOString();
    const message = `${this.logPrefix} [${timestamp}] Security Event: ${eventType} - ${details}`;
    console.warn(message);

    // TODO: Implement persistent logging to backend service
  }
}