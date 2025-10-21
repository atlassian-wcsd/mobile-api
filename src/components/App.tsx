import React, { useState, useEffect } from 'react';
import { AppleLoginButton } from './AppleLoginButton';
import { SignatureCanvas } from './SignatureCanvas';
import { FeedbackButton } from './FeedbackButton';
import { AppleUser } from '../models/AppleUser';
import { Signature } from '../models/Signature';

interface AppProps {
  className?: string;
}

export const App: React.FC<AppProps> = ({ className = '' }) => {
  const [user, setUser] = useState<AppleUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [currentSignature, setCurrentSignature] = useState<Signature | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<string>('');

  useEffect(() => {
    // Check for existing authentication on app load
    const storedUser = localStorage.getItem('currentUser');
    if (storedUser) {
      try {
        const parsedUser = JSON.parse(storedUser);
        setUser(parsedUser);
        setIsAuthenticated(true);
      } catch (error) {
        console.error('Failed to parse stored user:', error);
        localStorage.removeItem('currentUser');
      }
    }
  }, []);

  const handleLoginSuccess = (authenticatedUser: AppleUser) => {
    setUser(authenticatedUser);
    setIsAuthenticated(true);
    localStorage.setItem('currentUser', JSON.stringify(authenticatedUser));
    console.log('User logged in successfully:', authenticatedUser);
  };

  const handleLoginError = (error: string) => {
    console.error('Login failed:', error);
    setFeedbackMessage(`Login failed: ${error}`);
    setTimeout(() => setFeedbackMessage(''), 5000);
  };

  const handleSignatureSave = (signature: Signature) => {
    setSignatures(prev => [...prev, signature]);
    setCurrentSignature(signature);
    console.log('Signature saved:', signature);
  };

  const handleSignatureClear = () => {
    setCurrentSignature(null);
  };

  const handleLogout = () => {
    setUser(null);
    setIsAuthenticated(false);
    setSignatures([]);
    setCurrentSignature(null);
    localStorage.removeItem('currentUser');
  };

  const handleFeedbackSubmitted = (feedbackId: string) => {
    setFeedbackMessage(`Thank you for your feedback! Reference ID: ${feedbackId}`);
    setTimeout(() => setFeedbackMessage(''), 5000);
  };

  const handleFeedbackError = (error: string) => {
    setFeedbackMessage(`Failed to submit feedback: ${error}`);
    setTimeout(() => setFeedbackMessage(''), 5000);
  };

  return (
    <div className={`app ${className}`} style={{
      minHeight: '100vh',
      backgroundColor: '#f5f5f5',
      padding: '20px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      {/* Header */}
      <header style={{
        backgroundColor: 'white',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '20px',
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <h1 style={{ margin: 0, color: '#333' }}>Signature App</h1>
        {isAuthenticated && user && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <span style={{ color: '#666' }}>
              Welcome, {user.firstName || user.email || 'User'}!
            </span>
            <button
              onClick={handleLogout}
              style={{
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                padding: '8px 16px',
                cursor: 'pointer',
                fontSize: '14px'
              }}
            >
              Logout
            </button>
          </div>
        )}
      </header>

      {/* Feedback Message */}
      {feedbackMessage && (
        <div style={{
          backgroundColor: feedbackMessage.includes('failed') || feedbackMessage.includes('Failed') ? '#f8d7da' : '#d4edda',
          color: feedbackMessage.includes('failed') || feedbackMessage.includes('Failed') ? '#721c24' : '#155724',
          border: `1px solid ${feedbackMessage.includes('failed') || feedbackMessage.includes('Failed') ? '#f5c6cb' : '#c3e6cb'}`,
          borderRadius: '4px',
          padding: '12px',
          marginBottom: '20px'
        }}>
          {feedbackMessage}
        </div>
      )}

      {/* Main Content */}
      <main style={{
        backgroundColor: 'white',
        borderRadius: '8px',
        padding: '20px',
        boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
      }}>
        {!isAuthenticated ? (
          <div style={{ textAlign: 'center', padding: '40px 20px' }}>
            <h2 style={{ marginBottom: '16px', color: '#333' }}>Welcome to Signature App</h2>
            <p style={{ marginBottom: '32px', color: '#666', fontSize: '16px' }}>
              Please sign in with your Apple ID to start creating digital signatures.
            </p>
            <AppleLoginButton
              onSuccess={handleLoginSuccess}
              onError={handleLoginError}
            />
          </div>
        ) : (
          <div>
            <h2 style={{ marginBottom: '20px', color: '#333' }}>Create Your Signature</h2>
            <p style={{ marginBottom: '20px', color: '#666' }}>
              Draw your signature in the canvas below. You can clear and redraw as needed.
            </p>
            
            <SignatureCanvas
              width={600}
              height={200}
              onSave={handleSignatureSave}
              onClear={handleSignatureClear}
              className="signature-canvas"
            />

            {currentSignature && (
              <div style={{ marginTop: '20px' }}>
                <h3 style={{ marginBottom: '12px', color: '#333' }}>Current Signature</h3>
                <div style={{
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  padding: '12px',
                  backgroundColor: '#f9f9f9'
                }}>
                  <img
                    src={currentSignature.imageData}
                    alt="Current signature"
                    style={{
                      maxWidth: '100%',
                      height: 'auto',
                      border: '1px solid #ccc'
                    }}
                  />
                  <div style={{ marginTop: '8px', fontSize: '12px', color: '#666' }}>
                    Created: {currentSignature.createdAt.toLocaleString()}
                  </div>
                </div>
              </div>
            )}

            {signatures.length > 1 && (
              <div style={{ marginTop: '20px' }}>
                <h3 style={{ marginBottom: '12px', color: '#333' }}>
                  Signature History ({signatures.length} signatures)
                </h3>
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
                  gap: '12px'
                }}>
                  {signatures.slice(-5).map((signature, index) => (
                    <div
                      key={signature.id}
                      style={{
                        border: '1px solid #ddd',
                        borderRadius: '4px',
                        padding: '8px',
                        backgroundColor: '#f9f9f9',
                        cursor: 'pointer'
                      }}
                      onClick={() => setCurrentSignature(signature)}
                    >
                      <img
                        src={signature.imageData}
                        alt={`Signature ${index + 1}`}
                        style={{
                          width: '100%',
                          height: '60px',
                          objectFit: 'contain',
                          border: '1px solid #ccc'
                        }}
                      />
                      <div style={{ fontSize: '10px', color: '#666', marginTop: '4px' }}>
                        {signature.createdAt.toLocaleDateString()}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      {/* Footer */}
      <footer style={{
        textAlign: 'center',
        padding: '20px',
        color: '#666',
        fontSize: '14px'
      }}>
        <p>
          Need help or have suggestions? Use the feedback button to let us know!
        </p>
      </footer>

      {/* Feedback Button - Always visible */}
      <FeedbackButton
        authToken={user?.authToken}
        userEmail={user?.email}
        position="bottom-right"
        onFeedbackSubmitted={handleFeedbackSubmitted}
        onError={handleFeedbackError}
      />

      {/* Global Styles */}
      <style>{`
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        
        .signature-canvas canvas {
          border: 2px solid #ddd;
          border-radius: 4px;
          cursor: crosshair;
        }
        
        .signature-canvas canvas:hover {
          border-color: #007bff;
        }
        
        .feedback-button:hover {
          transform: translateY(-2px);
          box-shadow: 0 6px 16px rgba(0, 123, 255, 0.4);
        }
        
        .apple-login-button:hover {
          opacity: 0.9;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
          .app {
            padding: 10px;
          }
          
          .signature-canvas canvas {
            width: 100%;
            max-width: 100%;
          }
          
          header {
            flex-direction: column;
            gap: 12px;
            text-align: center;
          }
        }
      `}</style>
    </div>
  );
};

export default App;