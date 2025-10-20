import React, { useState } from 'react';
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
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const handleAppleLoginSuccess = (appleUser: AppleUser) => {
    setUser(appleUser);
    setNotification({
      type: 'success',
      message: `Welcome, ${appleUser.fullName || appleUser.email || 'User'}!`
    });
    
    // Clear notification after 3 seconds
    setTimeout(() => setNotification(null), 3000);
  };

  const handleAppleLoginError = (error: string) => {
    setNotification({
      type: 'error',
      message: `Login failed: ${error}`
    });
    
    // Clear notification after 5 seconds
    setTimeout(() => setNotification(null), 5000);
  };

  const handleSignatureSave = (signature: Signature) => {
    setSignatures(prev => [...prev, signature]);
    setNotification({
      type: 'success',
      message: 'Signature saved successfully!'
    });
    
    // Clear notification after 3 seconds
    setTimeout(() => setNotification(null), 3000);
  };

  const handleFeedbackSubmitted = (feedbackId: string) => {
    setNotification({
      type: 'success',
      message: `Thank you for your feedback! (ID: ${feedbackId})`
    });
    
    // Clear notification after 5 seconds
    setTimeout(() => setNotification(null), 5000);
  };

  const handleFeedbackError = (error: string) => {
    setNotification({
      type: 'error',
      message: `Feedback submission failed: ${error}`
    });
    
    // Clear notification after 5 seconds
    setTimeout(() => setNotification(null), 5000);
  };

  return (
    <div className={`app ${className}`} style={appStyles.container}>
      {/* Header */}
      <header style={appStyles.header}>
        <h1 style={appStyles.title}>Signature App</h1>
        <p style={appStyles.subtitle}>
          Create digital signatures and provide feedback
        </p>
      </header>

      {/* Notification */}
      {notification && (
        <div style={{
          ...appStyles.notification,
          ...appStyles[`notification${notification.type.charAt(0).toUpperCase() + notification.type.slice(1)}`]
        }}>
          {notification.message}
        </div>
      )}

      {/* Main Content */}
      <main style={appStyles.main}>
        {/* Authentication Section */}
        <section style={appStyles.section}>
          <h2 style={appStyles.sectionTitle}>Authentication</h2>
          {user ? (
            <div style={appStyles.userInfo}>
              <p>✓ Signed in as: <strong>{user.fullName || user.email || 'User'}</strong></p>
              <p>User ID: <code>{user.id}</code></p>
            </div>
          ) : (
            <div style={appStyles.loginSection}>
              <p>Sign in to save your signatures and provide personalized feedback:</p>
              <AppleLoginButton
                onSuccess={handleAppleLoginSuccess}
                onError={handleAppleLoginError}
              />
            </div>
          )}
        </section>

        {/* Signature Section */}
        <section style={appStyles.section}>
          <h2 style={appStyles.sectionTitle}>Digital Signature</h2>
          <p>Create your digital signature below:</p>
          <SignatureCanvas
            width={600}
            height={200}
            onSave={handleSignatureSave}
            className="signature-canvas"
          />
          
          {signatures.length > 0 && (
            <div style={appStyles.signaturesHistory}>
              <h3>Saved Signatures ({signatures.length})</h3>
              <div style={appStyles.signaturesGrid}>
                {signatures.slice(-3).map((sig, index) => (
                  <div key={sig.id} style={appStyles.signatureItem}>
                    <img 
                      src={sig.imageData} 
                      alt={`Signature ${index + 1}`}
                      style={appStyles.signatureImage}
                    />
                    <p style={appStyles.signatureDate}>
                      {sig.createdAt.toLocaleDateString()}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>

        {/* Features Section */}
        <section style={appStyles.section}>
          <h2 style={appStyles.sectionTitle}>App Features</h2>
          <div style={appStyles.featuresGrid}>
            <div style={appStyles.featureCard}>
              <h3>🍎 Apple Sign-In</h3>
              <p>Secure authentication with Apple ID</p>
            </div>
            <div style={appStyles.featureCard}>
              <h3>✍️ Digital Signatures</h3>
              <p>Create and save digital signatures</p>
            </div>
            <div style={appStyles.featureCard}>
              <h3>💬 User Feedback</h3>
              <p>Share your thoughts and suggestions</p>
            </div>
            <div style={appStyles.featureCard}>
              <h3>☁️ Cloud Storage</h3>
              <p>Your data is securely stored in the cloud</p>
            </div>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer style={appStyles.footer}>
        <p>&copy; 2024 Signature App. All rights reserved.</p>
        <p>
          Having issues or suggestions? 
          <button 
            style={appStyles.feedbackLink}
            onClick={() => {
              // This will be handled by the floating feedback button
              // but we can also trigger it programmatically
            }}
          >
            Send Feedback
          </button>
        </p>
      </footer>

      {/* Floating Feedback Button */}
      <FeedbackButton
        floating={true}
        position="bottom-right"
        userInfo={user ? {
          userId: user.id,
          email: user.email,
          name: user.fullName
        } : undefined}
        onFeedbackSubmitted={handleFeedbackSubmitted}
        onFeedbackError={handleFeedbackError}
      />

      {/* CSS for animations */}
      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(-10px); }
          to { opacity: 1; transform: translateY(0); }
        }
        
        @keyframes slideIn {
          from { transform: translateX(100%); }
          to { transform: translateX(0); }
        }
        
        .app {
          animation: fadeIn 0.5s ease-out;
        }
        
        .signature-canvas {
          border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
      `}</style>
    </div>
  );
};

// Styles
const appStyles = {
  container: {
    minHeight: '100vh',
    backgroundColor: '#f8f9fa',
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    lineHeight: 1.6,
    color: '#333'
  },
  header: {
    backgroundColor: '#fff',
    padding: '2rem 1rem',
    textAlign: 'center' as const,
    borderBottom: '1px solid #e0e0e0',
    boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
  },
  title: {
    margin: '0 0 0.5rem 0',
    fontSize: '2.5rem',
    fontWeight: '700',
    color: '#2c3e50'
  },
  subtitle: {
    margin: 0,
    fontSize: '1.1rem',
    color: '#666',
    fontWeight: '400'
  },
  notification: {
    padding: '1rem',
    margin: '1rem',
    borderRadius: '6px',
    fontWeight: '500',
    animation: 'slideIn 0.3s ease-out'
  },
  notificationSuccess: {
    backgroundColor: '#d4edda',
    color: '#155724',
    border: '1px solid #c3e6cb'
  },
  notificationError: {
    backgroundColor: '#f8d7da',
    color: '#721c24',
    border: '1px solid #f5c6cb'
  },
  notificationInfo: {
    backgroundColor: '#d1ecf1',
    color: '#0c5460',
    border: '1px solid #bee5eb'
  },
  main: {
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '2rem 1rem'
  },
  section: {
    backgroundColor: '#fff',
    padding: '2rem',
    marginBottom: '2rem',
    borderRadius: '8px',
    boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)'
  },
  sectionTitle: {
    margin: '0 0 1rem 0',
    fontSize: '1.5rem',
    fontWeight: '600',
    color: '#2c3e50'
  },
  userInfo: {
    padding: '1rem',
    backgroundColor: '#e8f5e8',
    borderRadius: '6px',
    border: '1px solid #c3e6cb'
  },
  loginSection: {
    textAlign: 'center' as const
  },
  signaturesHistory: {
    marginTop: '2rem',
    paddingTop: '2rem',
    borderTop: '1px solid #e0e0e0'
  },
  signaturesGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '1rem',
    marginTop: '1rem'
  },
  signatureItem: {
    textAlign: 'center' as const,
    padding: '1rem',
    border: '1px solid #e0e0e0',
    borderRadius: '6px',
    backgroundColor: '#f8f9fa'
  },
  signatureImage: {
    maxWidth: '100%',
    height: '80px',
    objectFit: 'contain' as const,
    border: '1px solid #ddd',
    borderRadius: '4px',
    backgroundColor: '#fff'
  },
  signatureDate: {
    margin: '0.5rem 0 0 0',
    fontSize: '0.9rem',
    color: '#666'
  },
  featuresGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
    gap: '1.5rem',
    marginTop: '1rem'
  },
  featureCard: {
    padding: '1.5rem',
    backgroundColor: '#f8f9fa',
    borderRadius: '8px',
    border: '1px solid #e0e0e0',
    textAlign: 'center' as const
  },
  footer: {
    backgroundColor: '#2c3e50',
    color: '#fff',
    padding: '2rem 1rem',
    textAlign: 'center' as const,
    marginTop: '2rem'
  },
  feedbackLink: {
    background: 'none',
    border: 'none',
    color: '#3498db',
    textDecoration: 'underline',
    cursor: 'pointer',
    fontSize: 'inherit',
    marginLeft: '0.5rem'
  }
};

export default App;