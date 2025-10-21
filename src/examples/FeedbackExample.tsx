import React, { useState } from 'react';
import { 
  FeedbackForm, 
  FloatingFeedbackButton, 
  InlineFeedbackButton, 
  MenuFeedbackButton 
} from '../components/FeedbackButton';
import { FeedbackCategory } from '../models/Feedback';

/**
 * Example component demonstrating different ways to integrate the feedback system
 */
export const FeedbackExample: React.FC = () => {
  const [showForm, setShowForm] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState<string>('');

  const handleFeedbackSuccess = (feedbackId: string) => {
    setFeedbackMessage(`✅ Feedback submitted successfully! ID: ${feedbackId}`);
    setTimeout(() => setFeedbackMessage(''), 5000);
  };

  const handleFeedbackError = (error: string) => {
    setFeedbackMessage(`❌ Error: ${error}`);
    setTimeout(() => setFeedbackMessage(''), 5000);
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'Arial, sans-serif' }}>
      <h1>Feedback System Examples</h1>
      
      {feedbackMessage && (
        <div style={{
          padding: '10px',
          marginBottom: '20px',
          backgroundColor: feedbackMessage.includes('✅') ? '#d4edda' : '#f8d7da',
          border: `1px solid ${feedbackMessage.includes('✅') ? '#c3e6cb' : '#f5c6cb'}`,
          borderRadius: '4px',
          color: feedbackMessage.includes('✅') ? '#155724' : '#721c24'
        }}>
          {feedbackMessage}
        </div>
      )}

      <section style={{ marginBottom: '40px' }}>
        <h2>1. Floating Feedback Button</h2>
        <p>A floating button that stays in a fixed position on the screen.</p>
        <div style={{ position: 'relative', height: '200px', border: '1px dashed #ccc', borderRadius: '8px' }}>
          <p style={{ padding: '20px', margin: 0 }}>
            This represents your app content. The floating feedback button appears in the bottom-right corner.
          </p>
          <FloatingFeedbackButton
            userId="example-user-123"
            position="bottom-right"
            onFeedbackSubmitted={handleFeedbackSuccess}
            onFeedbackError={handleFeedbackError}
          />
        </div>
      </section>

      <section style={{ marginBottom: '40px' }}>
        <h2>2. Inline Feedback Buttons</h2>
        <p>Buttons that can be placed inline with your content.</p>
        
        <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
          <InlineFeedbackButton
            userId="example-user-123"
            initialCategory={FeedbackCategory.GENERAL_FEEDBACK}
            onFeedbackSubmitted={handleFeedbackSuccess}
            onFeedbackError={handleFeedbackError}
          />
          
          <InlineFeedbackButton
            userId="example-user-123"
            initialCategory={FeedbackCategory.BUG_REPORT}
            onFeedbackSubmitted={handleFeedbackSuccess}
            onFeedbackError={handleFeedbackError}
            style={{ backgroundColor: '#dc3545', borderColor: '#dc3545' }}
          />
          
          <InlineFeedbackButton
            userId="example-user-123"
            initialCategory={FeedbackCategory.FEATURE_REQUEST}
            onFeedbackSubmitted={handleFeedbackSuccess}
            onFeedbackError={handleFeedbackError}
            style={{ backgroundColor: '#28a745', borderColor: '#28a745' }}
          />
        </div>
      </section>

      <section style={{ marginBottom: '40px' }}>
        <h2>3. Menu Feedback Button</h2>
        <p>A button styled for use in navigation menus or dropdowns.</p>
        
        <div style={{ 
          border: '1px solid #ddd', 
          borderRadius: '8px', 
          padding: '16px',
          backgroundColor: '#f8f9fa'
        }}>
          <h3 style={{ margin: '0 0 16px 0' }}>Navigation Menu</h3>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            <li style={{ marginBottom: '8px' }}>
              <a href="#" style={{ textDecoration: 'none', color: '#333' }}>Home</a>
            </li>
            <li style={{ marginBottom: '8px' }}>
              <a href="#" style={{ textDecoration: 'none', color: '#333' }}>Profile</a>
            </li>
            <li style={{ marginBottom: '8px' }}>
              <a href="#" style={{ textDecoration: 'none', color: '#333' }}>Settings</a>
            </li>
            <li>
              <MenuFeedbackButton
                userId="example-user-123"
                onFeedbackSubmitted={handleFeedbackSuccess}
                onFeedbackError={handleFeedbackError}
              />
            </li>
          </ul>
        </div>
      </section>

      <section style={{ marginBottom: '40px' }}>
        <h2>4. Manual Form Control</h2>
        <p>You can also control the feedback form manually.</p>
        
        <button 
          onClick={() => setShowForm(true)}
          style={{
            padding: '12px 24px',
            backgroundColor: '#007bff',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer'
          }}
        >
          Open Feedback Form Manually
        </button>

        <FeedbackForm
          isOpen={showForm}
          onClose={() => setShowForm(false)}
          onSuccess={handleFeedbackSuccess}
          onError={handleFeedbackError}
          userId="example-user-123"
          initialCategory={FeedbackCategory.USER_EXPERIENCE}
        />
      </section>

      <section style={{ marginBottom: '40px' }}>
        <h2>5. Different Categories</h2>
        <p>You can pre-select different feedback categories based on context.</p>
        
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          {Object.values(FeedbackCategory).map((category) => (
            <div key={category} style={{ 
              border: '1px solid #ddd', 
              borderRadius: '8px', 
              padding: '16px',
              textAlign: 'center'
            }}>
              <h4 style={{ margin: '0 0 12px 0' }}>
                {category.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
              </h4>
              <InlineFeedbackButton
                userId="example-user-123"
                initialCategory={category}
                onFeedbackSubmitted={handleFeedbackSuccess}
                onFeedbackError={handleFeedbackError}
                style={{ width: '100%' }}
              />
            </div>
          ))}
        </div>
      </section>

      <section>
        <h2>6. Anonymous Feedback</h2>
        <p>Feedback can also be submitted without user authentication.</p>
        
        <InlineFeedbackButton
          // No userId provided - anonymous feedback
          initialCategory={FeedbackCategory.GENERAL_FEEDBACK}
          onFeedbackSubmitted={handleFeedbackSuccess}
          onFeedbackError={handleFeedbackError}
          style={{ backgroundColor: '#6c757d', borderColor: '#6c757d' }}
        />
      </section>
    </div>
  );
};

export default FeedbackExample;