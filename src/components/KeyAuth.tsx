import React, { useState } from 'react';
import { AuthService } from '../services/AuthService';
import { AuthRequest, AuthResponse } from '../models/Auth';

interface KeyAuthProps {
  onAuthSuccess: (response: AuthResponse) => void;
  onAuthFailure: (error: string) => void;
}

/**
 * Component for key-based authentication
 */
export const KeyAuth: React.FC<KeyAuthProps> = ({ onAuthSuccess, onAuthFailure }) => {
  const [keyId, setKeyId] = useState('');
  const [keyValue, setKeyValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const authService = new AuthService();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const request: AuthRequest = {
        keyId,
        keyValue
      };

      const response = await authService.authenticate(request);

      if (response.success) {
        onAuthSuccess(response);
      } else {
        setError(response.error || 'Authentication failed');
        onAuthFailure(response.error || 'Authentication failed');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An unexpected error occurred';
      setError(errorMessage);
      onAuthFailure(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="key-auth-container">
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="keyId">Key ID:</label>
          <input
            type="text"
            id="keyId"
            value={keyId}
            onChange={(e) => setKeyId(e.target.value)}
            required
            disabled={isLoading}
            placeholder="Enter your key ID"
          />
        </div>

        <div className="form-group">
          <label htmlFor="keyValue">Key Value:</label>
          <input
            type="password"
            id="keyValue"
            value={keyValue}
            onChange={(e) => setKeyValue(e.target.value)}
            required
            disabled={isLoading}
            placeholder="Enter your key value"
          />
        </div>

        {error && (
          <div className="error-message">
            {error}
          </div>
        )}

        <button 
          type="submit" 
          disabled={isLoading}
          className="auth-button"
        >
          {isLoading ? 'Authenticating...' : 'Login'}
        </button>
      </form>
    </div>
  );
};