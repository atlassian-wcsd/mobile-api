import React, { useState, useCallback } from 'react';
import { LoginRequest, LoginResponse, AuthError } from '../models/User';
import { AuthenticationService } from '../services/AuthenticationService';

interface LoginFormProps {
  onLoginSuccess: (response: LoginResponse) => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [requiresMfa, setRequiresMfa] = useState(false);
  const [showPasswordReset, setShowPasswordReset] = useState(false);

  const authService = new AuthenticationService();

  const validatePassword = (password: string): boolean => {
    const hasMinLength = password.length >= 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[@$!%*?&]/.test(password);

    return hasMinLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (!email || !password) {
        setError('Please enter both email and password');
        return;
      }

      const loginRequest: LoginRequest = {
        email,
        password,
        mfaCode: requiresMfa ? mfaCode : undefined
      };

      const response = await authService.login(loginRequest);

      if (response.success) {
        onLoginSuccess(response);
      } else if (response.requiresMfa) {
        setRequiresMfa(true);
        setError('Please enter your MFA code');
      } else {
        setError(response.error || 'Login failed');
        if (response.error === AuthError.ACCOUNT_LOCKED) {
          setTimeout(() => setError(null), 15 * 60 * 1000); // Clear error after lockout period
        }
      }
    } catch (err) {
      setError('An unexpected error occurred');
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handlePasswordReset = async () => {
    if (!email) {
      setError('Please enter your email address');
      return;
    }

    try {
      await authService.initiatePasswordReset(email);
      setShowPasswordReset(false);
      setError('Password reset instructions have been sent to your email');
    } catch (err) {
      setError('Failed to initiate password reset');
      console.error('Password reset error:', err);
    }
  };

  return (
    <div className="login-form-container">
      <form onSubmit={handleSubmit} className="login-form">
        <h2>Login</h2>
        
        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        <div className="form-group">
          <label htmlFor="email">Email:</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={loading}
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password:</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={loading}
            required
          />
          <div className="password-requirements">
            Password must contain at least 8 characters, including uppercase, lowercase, 
            numbers, and special characters.
          </div>
        </div>

        {requiresMfa && (
          <div className="form-group">
            <label htmlFor="mfaCode">MFA Code:</label>
            <input
              type="text"
              id="mfaCode"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              disabled={loading}
              required
            />
          </div>
        )}

        <div className="form-actions">
          <button 
            type="submit" 
            disabled={loading}
            className="login-button"
          >
            {loading ? 'Logging in...' : 'Login'}
          </button>

          <button
            type="button"
            onClick={() => setShowPasswordReset(true)}
            disabled={loading}
            className="forgot-password-button"
          >
            Forgot Password?
          </button>
        </div>
      </form>

      {showPasswordReset && (
        <div className="password-reset-modal">
          <div className="modal-content">
            <h3>Reset Password</h3>
            <p>Enter your email address to receive password reset instructions.</p>
            
            <div className="form-group">
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Email address"
                required
              />
            </div>

            <div className="modal-actions">
              <button 
                onClick={handlePasswordReset}
                className="reset-button"
              >
                Send Reset Instructions
              </button>
              <button 
                onClick={() => setShowPasswordReset(false)}
                className="cancel-button"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};