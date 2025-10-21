import React, { useState } from 'react';
import { FeedbackForm } from './FeedbackForm';
import { FeedbackButton } from './FeedbackButton';
import { feedbackService } from '../services/FeedbackService';
import { FeedbackType, FeedbackCategory } from '../models/Feedback';

/**
 * Test component for the feedback system
 * This component demonstrates how to use the feedback components
 * and can be used for testing the feedback functionality
 */
export const FeedbackTest: React.FC = () => {
  const [showForm, setShowForm] = useState(false);
  const [testResults, setTestResults] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const addTestResult = (result: string) => {
    setTestResults(prev => [...prev, `${new Date().toLocaleTimeString()}: ${result}`]);
  };

  const testValidation = () => {
    addTestResult('Testing validation...');
    
    // Test valid request
    const validRequest = {
      type: FeedbackType.GENERAL_FEEDBACK,
      category: FeedbackCategory.GENERAL,
      subject: 'Test feedback',
      message: 'This is a test message for validation'
    };
    
    const validationResult = feedbackService.validateFeedbackRequest(validRequest);
    if (validationResult.isValid) {
      addTestResult('✅ Valid request passed validation');
    } else {
      addTestResult('❌ Valid request failed validation: ' + validationResult.errors.join(', '));
    }

    // Test invalid request
    const invalidRequest = {
      type: FeedbackType.GENERAL_FEEDBACK,
      category: FeedbackCategory.GENERAL,
      subject: 'Hi', // Too short
      message: 'Short' // Too short
    };
    
    const invalidValidationResult = feedbackService.validateFeedbackRequest(invalidRequest);
    if (!invalidValidationResult.isValid) {
      addTestResult('✅ Invalid request correctly failed validation');
    } else {
      addTestResult('❌ Invalid request incorrectly passed validation');
    }
  };

  const testDeviceInfo = () => {
    addTestResult('Testing device info collection...');
    const deviceInfo = feedbackService.getDeviceInfo();
    addTestResult(`✅ Device info collected: ${JSON.stringify(deviceInfo, null, 2)}`);
  };

  const testFeedbackSubmission = async () => {
    setIsLoading(true);
    addTestResult('Testing feedback submission...');
    
    try {
      const testFeedback = {
        type: FeedbackType.GENERAL_FEEDBACK,
        category: FeedbackCategory.GENERAL,
        subject: 'Test feedback submission',
        message: 'This is a test feedback submission to verify the system is working correctly.',
        rating: 5,
        email: 'test@example.com'
      };

      const response = await feedbackService.submitFeedback(testFeedback);
      
      if (response.success) {
        addTestResult(`✅ Feedback submitted successfully: ${response.feedbackId}`);
      } else {
        addTestResult(`❌ Feedback submission failed: ${response.error || response.message}`);
      }
    } catch (error) {
      addTestResult(`❌ Feedback submission error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsLoading(false);
    }
  };

  const clearResults = () => {
    setTestResults([]);
  };

  return (
    <div style={{
      padding: '20px',
      maxWidth: '800px',
      margin: '0 auto',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif'
    }}>
      <h1>Feedback System Test</h1>
      
      <div style={{
        backgroundColor: '#f8f9fa',
        border: '1px solid #dee2e6',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '20px'
      }}>
        <h2>Test Controls</h2>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button
            onClick={testValidation}
            style={{
              backgroundColor: '#007bff',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              padding: '8px 16px',
              cursor: 'pointer'
            }}
          >
            Test Validation
          </button>
          
          <button
            onClick={testDeviceInfo}
            style={{
              backgroundColor: '#28a745',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              padding: '8px 16px',
              cursor: 'pointer'
            }}
          >
            Test Device Info
          </button>
          
          <button
            onClick={testFeedbackSubmission}
            disabled={isLoading}
            style={{
              backgroundColor: isLoading ? '#6c757d' : '#ffc107',
              color: isLoading ? 'white' : 'black',
              border: 'none',
              borderRadius: '4px',
              padding: '8px 16px',
              cursor: isLoading ? 'not-allowed' : 'pointer'
            }}
          >
            {isLoading ? 'Testing...' : 'Test Submission'}
          </button>
          
          <button
            onClick={() => setShowForm(true)}
            style={{
              backgroundColor: '#17a2b8',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              padding: '8px 16px',
              cursor: 'pointer'
            }}
          >
            Open Feedback Form
          </button>
          
          <button
            onClick={clearResults}
            style={{
              backgroundColor: '#dc3545',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              padding: '8px 16px',
              cursor: 'pointer'
            }}
          >
            Clear Results
          </button>
        </div>
      </div>

      <div style={{
        backgroundColor: 'white',
        border: '1px solid #dee2e6',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '20px'
      }}>
        <h2>Test Results</h2>
        <div style={{
          backgroundColor: '#f8f9fa',
          border: '1px solid #dee2e6',
          borderRadius: '4px',
          padding: '12px',
          minHeight: '200px',
          maxHeight: '400px',
          overflowY: 'auto',
          fontFamily: 'monospace',
          fontSize: '14px'
        }}>
          {testResults.length === 0 ? (
            <div style={{ color: '#6c757d' }}>No test results yet. Run some tests to see results here.</div>
          ) : (
            testResults.map((result, index) => (
              <div key={index} style={{ marginBottom: '4px' }}>
                {result}
              </div>
            ))
          )}
        </div>
      </div>

      <div style={{
        backgroundColor: 'white',
        border: '1px solid #dee2e6',
        borderRadius: '8px',
        padding: '20px'
      }}>
        <h2>Feedback Components Demo</h2>
        <p>The feedback button below demonstrates the floating feedback button component:</p>
        
        <div style={{ position: 'relative', height: '100px', border: '1px dashed #ccc', borderRadius: '4px' }}>
          <FeedbackButton
            position="bottom-right"
            onFeedbackSubmitted={(feedbackId) => {
              addTestResult(`✅ Feedback submitted via button: ${feedbackId}`);
            }}
            onError={(error) => {
              addTestResult(`❌ Feedback button error: ${error}`);
            }}
          />
        </div>
      </div>

      <FeedbackForm
        isOpen={showForm}
        onClose={() => setShowForm(false)}
        onSuccess={(feedbackId) => {
          setShowForm(false);
          addTestResult(`✅ Feedback submitted via form: ${feedbackId}`);
        }}
        onError={(error) => {
          addTestResult(`❌ Feedback form error: ${error}`);
        }}
      />
    </div>
  );
};

export default FeedbackTest;