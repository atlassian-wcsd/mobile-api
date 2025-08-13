import React, { useState } from 'react';
import { AppleLoginButton } from './AppleLoginButton';
import { SignatureCanvas } from './SignatureCanvas';
import { FeedbackButton } from './FeedbackButton';
import { AppleUser } from '../models/AppleUser';
import { Signature } from '../models/Signature';

const App: React.FC = () => {
  const [user, setUser] = useState<AppleUser | null>(null);
  const [signatures, setSignatures] = useState<Signature[]>([]);
  const [showSuccessMessage, setShowSuccessMessage] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleLoginSuccess = (user: AppleUser) => {
    setUser(user);
    setErrorMessage(null);
    console.log('User logged in:', user);
  };

  const handleLoginError = (error: string) => {
    setErrorMessage(error);
    console.error('Login error:', error);
  };

  const handleSignatureSave = (signature: Signature) => {
    setSignatures(prev => [...prev, signature]);
    setShowSuccessMessage(true);
    setTimeout(() => setShowSuccessMessage(false), 3000);
    console.log('Signature saved:', signature);
  };

  const handleFeedbackSubmitted = (feedbackId: string) => {
    console.log('Feedback submitted with ID:', feedbackId);
    // You could show a notification or update UI state here
  };

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#f5f5f5',
      padding: '20px'
    }}>
      {/* Header */}
      <header style={{
        backgroundColor: '#fff',
        padding: '20px',
        borderRadius: '8px',
        marginBottom: '20px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <h1 style={{ margin: 0, color: '#333' }}>Signature App</h1>
        
        {!user ? (
          <AppleLoginButton
            onSuccess={handleLoginSuccess}
            onError={handleLoginError}
          />
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ color: '#666' }}>
              Welcome, {user.fullName || user.email || 'User'}!
            </span>
            <button
              onClick={() => setUser(null)}
              style={{
                padding: '8px 16px',
                backgroundColor: '#dc3545',
                color: '#fff',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Sign Out
            </button>
          </div>
        )}
      </header>

      {/* Error Message */}
      {errorMessage && (
        <div style={{
          backgroundColor: '#f8d7da',
          color: '#721c24',
          border: '1px solid #f5c6cb',
          borderRadius: '4px',
          padding: '12px',
          marginBottom: '20px'
        }}>
          {errorMessage}
        </div>
      )}

      {/* Success Message */}
      {showSuccessMessage && (
        <div style={{
          backgroundColor: '#d4edda',
          color: '#155724',
          border: '1px solid #c3e6cb',
          borderRadius: '4px',
          padding: '12px',
          marginBottom: '20px'
        }}>
          Signature saved successfully!
        </div>
      )}

      {/* Main Content */}
      <main style={{
        display: 'grid',
        gap: '20px',
        gridTemplateColumns: 'repeat(auto-fit, minmax(500px, 1fr))'
      }}>
        {/* Signature Canvas Section */}
        <section style={{
          backgroundColor: '#fff',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h2 style={{ marginTop: 0, color: '#333' }}>Create Signature</h2>
          <p style={{ color: '#666', marginBottom: '20px' }}>
            Draw your signature in the canvas below. You can clear and redraw as needed.
          </p>
          
          <SignatureCanvas
            width={450}
            height={200}
            onSave={handleSignatureSave}
            onClear={() => console.log('Canvas cleared')}
          />
        </section>

        {/* Signatures History */}
        <section style={{
          backgroundColor: '#fff',
          padding: '24px',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
        }}>
          <h2 style={{ marginTop: 0, color: '#333' }}>Signature History</h2>
          
          {signatures.length === 0 ? (
            <p style={{ color: '#666' }}>No signatures created yet.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {signatures.map((signature, index) => (
                <div key={signature.id} style={{
                  border: '1px solid #ddd',
                  borderRadius: '4px',
                  padding: '12px'
                }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '8px'
                  }}>
                    <span style={{ fontWeight: '500' }}>
                      Signature #{index + 1}
                    </span>
                    <span style={{ fontSize: '14px', color: '#666' }}>
                      {signature.createdAt.toLocaleString()}
                    </span>
                  </div>
                  <img
                    src={signature.imageData}
                    alt={`Signature ${index + 1}`}
                    style={{
                      maxWidth: '100%',
                      height: 'auto',
                      border: '1px solid #eee',
                      borderRadius: '4px'
                    }}
                  />
                </div>
              ))}
            </div>
          )}
        </section>
      </main>

      {/* App Info */}
      <footer style={{
        backgroundColor: '#fff',
        padding: '20px',
        borderRadius: '8px',
        marginTop: '20px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
        textAlign: 'center'
      }}>
        <h3 style={{ marginTop: 0, color: '#333' }}>About This App</h3>
        <p style={{ color: '#666', margin: '0 0 16px 0' }}>
          This signature application allows you to create digital signatures using a canvas interface.
          You can sign in with Apple ID for a personalized experience and save your signatures.
        </p>
        <p style={{ color: '#666', fontSize: '14px', margin: 0 }}>
          Have feedback or suggestions? Use the feedback button to let us know!
        </p>
      </footer>

      {/* Floating Feedback Button */}
      <FeedbackButton
        position="bottom-right"
        userEmail={user?.email}
        onFeedbackSubmitted={handleFeedbackSubmitted}
      />
    </div>
  );
};

export default App;