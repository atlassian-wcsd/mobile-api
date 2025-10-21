import React, { useState, useEffect } from 'react';
import { AppleLoginButton } from './AppleLoginButton';
import { SignatureCanvas } from './SignatureCanvas';
import { FloatingFeedbackButton } from './FeedbackButton';
import { AppleUser } from '../models/AppleUser';
import { Signature } from '../models/Signature';
import { FeedbackCategory } from '../models/Feedback';

interface AppProps {
  className?: string;
}

export const App: React.FC<AppProps> = ({ className = '' }) => {
  const [user, setUser] = useState<AppleUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [currentView, setCurrentView] = useState<'login' | 'main'>('login');

  useEffect(() => {
    // Check for existing authentication on app load
    const savedUser = localStorage.getItem('currentUser');
    if (savedUser) {
      try {
        const parsedUser = JSON.parse(savedUser);
        setUser(parsedUser);
        setIsAuthenticated(true);
        setCurrentView('main');
      } catch (error) {
        console.error('Failed to parse saved user:', error);
        localStorage.removeItem('currentUser');
      }
    }
  }, []);

  const handleLoginSuccess = (user: AppleUser) => {
    setUser(user);
    setIsAuthenticated(true);
    setCurrentView('main');
    
    // Save user to localStorage for persistence
    localStorage.setItem('currentUser', JSON.stringify(user));
    
    console.log('User logged in successfully:', user);
  };

  const handleLoginError = (error: string) => {
    console.error('Login failed:', error);
    // You could show a toast notification here
  };

  const handleSignatureSave = (signature: Signature) => {
    setSignatures(prev => [...prev, signature]);
    console.log('Signature saved:', signature);
    // Here you would typically send the signature to your backend
  };

  const handleSignatureClear = () => {
    console.log('Signature canvas cleared');
  };

  const handleLogout = () => {
    setUser(null);
    setIsAuthenticated(false);
    setCurrentView('login');
    setSignatures([]);
    localStorage.removeItem('currentUser');
  };

  const handleFeedbackSubmitted = (feedbackId: string) => {
    console.log('Feedback submitted successfully:', feedbackId);
    // You could show a success notification here
  };

  const handleFeedbackError = (error: string) => {
    console.error('Feedback submission failed:', error);
    // You could show an error notification here
  };

  return (
    <div className={`app ${className}`} style={appStyles}>
      <header style={headerStyles}>
        <h1 style={titleStyles}>Signature App</h1>
        {isAuthenticated && user && (
          <div style={userInfoStyles}>
            <span>Welcome, {user.fullName || user.firstName || 'User'}!</span>
            <button onClick={handleLogout} style={logoutButtonStyles}>
              Logout
            </button>
          </div>
        )}
      </header>

      <main style={mainStyles}>
        {currentView === 'login' ? (
          <div style={loginContainerStyles}>
            <div style={loginCardStyles}>
              <h2 style={loginTitleStyles}>Welcome to Signature App</h2>
              <p style={loginDescriptionStyles}>
                Sign in with your Apple ID to start creating and managing your digital signatures.
              </p>
              <AppleLoginButton
                onSuccess={handleLoginSuccess}
                onError={handleLoginError}
                className="login-button"
              />
            </div>
          </div>
        ) : (
          <div style={mainContentStyles}>
            <section style={sectionStyles}>
              <h2 style={sectionTitleStyles}>Create Your Signature</h2>
              <p style={sectionDescriptionStyles}>
                Draw your signature in the canvas below. You can clear and redraw as needed.
              </p>
              <SignatureCanvas
                width={600}
                height={250}
                onSave={handleSignatureSave}
                onClear={handleSignatureClear}
                className="signature-canvas"
              />
            </section>

            {signatures.length > 0 && (
              <section style={sectionStyles}>
                <h2 style={sectionTitleStyles}>Your Signatures</h2>
                <div style={signaturesGridStyles}>
                  {signatures.map((signature) => (
                    <div key={signature.id} style={signatureItemStyles}>
                      <img
                        src={signature.imageData}
                        alt="Signature"
                        style={signatureImageStyles}
                      />
                      <div style={signatureMetaStyles}>
                        <small>
                          Created: {new Date(signature.createdAt).toLocaleDateString()}
                        </small>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            )}

            <section style={sectionStyles}>
              <h2 style={sectionTitleStyles}>About This App</h2>
              <p style={sectionDescriptionStyles}>
                This signature application allows you to create, save, and manage digital signatures.
                Your signatures are securely stored and can be used for document signing.
              </p>
              <div style={featuresStyles}>
                <div style={featureStyles}>
                  <h3>🔒 Secure Authentication</h3>
                  <p>Sign in securely with Apple ID</p>
                </div>
                <div style={featureStyles}>
                  <h3>✍️ Digital Signatures</h3>
                  <p>Create signatures with touch or mouse</p>
                </div>
                <div style={featureStyles}>
                  <h3>💾 Cloud Storage</h3>
                  <p>Your signatures are safely stored</p>
                </div>
              </div>
            </section>
          </div>
        )}
      </main>

      {/* Floating Feedback Button - always visible */}
      <FloatingFeedbackButton
        userId={user?.id}
        position="bottom-right"
        initialCategory={FeedbackCategory.GENERAL_FEEDBACK}
        onFeedbackSubmitted={handleFeedbackSubmitted}
        onFeedbackError={handleFeedbackError}
      />

      <footer style={footerStyles}>
        <p>&copy; 2024 Signature App. All rights reserved.</p>
      </footer>
    </div>
  );
};

// Styles
const appStyles: React.CSSProperties = {
  minHeight: '100vh',
  display: 'flex',
  flexDirection: 'column',
  fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
  backgroundColor: '#f8f9fa',
  color: '#333'
};

const headerStyles: React.CSSProperties = {
  backgroundColor: 'white',
  padding: '16px 24px',
  borderBottom: '1px solid #e9ecef',
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
};

const titleStyles: React.CSSProperties = {
  margin: 0,
  fontSize: '24px',
  fontWeight: '600',
  color: '#007bff'
};

const userInfoStyles: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: '16px'
};

const logoutButtonStyles: React.CSSProperties = {
  padding: '8px 16px',
  border: '1px solid #dc3545',
  borderRadius: '4px',
  backgroundColor: 'white',
  color: '#dc3545',
  cursor: 'pointer',
  fontSize: '14px'
};

const mainStyles: React.CSSProperties = {
  flex: 1,
  padding: '24px'
};

const loginContainerStyles: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'center',
  alignItems: 'center',
  minHeight: '60vh'
};

const loginCardStyles: React.CSSProperties = {
  backgroundColor: 'white',
  padding: '48px',
  borderRadius: '12px',
  boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
  textAlign: 'center',
  maxWidth: '400px',
  width: '100%'
};

const loginTitleStyles: React.CSSProperties = {
  marginBottom: '16px',
  fontSize: '28px',
  fontWeight: '600'
};

const loginDescriptionStyles: React.CSSProperties = {
  marginBottom: '32px',
  color: '#666',
  lineHeight: '1.5'
};

const mainContentStyles: React.CSSProperties = {
  maxWidth: '800px',
  margin: '0 auto'
};

const sectionStyles: React.CSSProperties = {
  backgroundColor: 'white',
  padding: '32px',
  borderRadius: '12px',
  marginBottom: '24px',
  boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
};

const sectionTitleStyles: React.CSSProperties = {
  marginBottom: '16px',
  fontSize: '24px',
  fontWeight: '600'
};

const sectionDescriptionStyles: React.CSSProperties = {
  marginBottom: '24px',
  color: '#666',
  lineHeight: '1.6'
};

const signaturesGridStyles: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
  gap: '16px'
};

const signatureItemStyles: React.CSSProperties = {
  border: '1px solid #e9ecef',
  borderRadius: '8px',
  padding: '12px',
  backgroundColor: '#f8f9fa'
};

const signatureImageStyles: React.CSSProperties = {
  width: '100%',
  height: 'auto',
  border: '1px solid #ddd',
  borderRadius: '4px'
};

const signatureMetaStyles: React.CSSProperties = {
  marginTop: '8px',
  color: '#666'
};

const featuresStyles: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
  gap: '24px',
  marginTop: '24px'
};

const featureStyles: React.CSSProperties = {
  textAlign: 'center'
};

const footerStyles: React.CSSProperties = {
  backgroundColor: 'white',
  padding: '16px 24px',
  borderTop: '1px solid #e9ecef',
  textAlign: 'center',
  color: '#666',
  fontSize: '14px'
};

export default App;