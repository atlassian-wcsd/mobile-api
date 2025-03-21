import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
} from 'react-native';
import { useNavigation, useRoute } from '@react-navigation/native';
import { verifyMFA, requestMFA } from '../services/auth';
import { SecurityLogger } from '../utils/securityLogger';

const securityLogger = new SecurityLogger();

const MFAVerificationScreen: React.FC = () => {
  const navigation = useNavigation();
  const route = useRoute();
  const [mfaCode, setMFACode] = useState('');
  const [error, setError] = useState('');
  const [timeLeft, setTimeLeft] = useState(300); // 5 minutes countdown
  const email = route.params?.email;

  useEffect(() => {
    // Start countdown timer
    const timer = setInterval(() => {
      setTimeLeft((prevTime) => {
        if (prevTime <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prevTime - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const handleMFASubmit = async () => {
    try {
      setError('');
      
      if (!mfaCode || mfaCode.length !== 6) {
        throw new Error('Please enter a valid 6-digit MFA code');
      }

      if (timeLeft === 0) {
        throw new Error('Verification code has expired. Please request a new one.');
      }

      const verificationResult = await verifyMFA(email, mfaCode);
      
      if (verificationResult.success) {
        securityLogger.logSuccess('mfa_verification', { email });
        navigation.navigate('Home');
      } else {
        throw new Error('Invalid verification code');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred during verification';
      setError(errorMessage);
      securityLogger.logFailure('mfa_verification', { email, error: errorMessage });
    }
  };

  const handleResendCode = async () => {
    try {
      await requestMFA(email);
      setTimeLeft(300); // Reset timer to 5 minutes
      setError('');
      Alert.alert('Success', 'A new verification code has been sent to your email');
      securityLogger.logSuccess('mfa_code_resent', { email });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to resend verification code';
      setError(errorMessage);
      securityLogger.logFailure('mfa_code_resend', { email, error: errorMessage });
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Two-Factor Authentication</Text>
      
      {error ? <Text style={styles.error}>{error}</Text> : null}

      <Text style={styles.description}>
        Please enter the 6-digit verification code sent to your email
      </Text>

      <Text style={styles.timer}>
        Time remaining: {formatTime(timeLeft)}
      </Text>
      
      <TextInput
        style={styles.input}
        placeholder="Enter 6-digit code"
        value={mfaCode}
        onChangeText={setMFACode}
        keyboardType="number-pad"
        maxLength={6}
        autoFocus
      />

      <TouchableOpacity
        style={[styles.button, timeLeft === 0 && styles.disabledButton]}
        onPress={handleMFASubmit}
        disabled={timeLeft === 0}
      >
        <Text style={styles.buttonText}>Verify</Text>
      </TouchableOpacity>

      <TouchableOpacity
        style={styles.resendButton}
        onPress={handleResendCode}
      >
        <Text style={styles.resendButtonText}>Resend Code</Text>
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    justifyContent: 'center',
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  description: {
    textAlign: 'center',
    marginBottom: 20,
    fontSize: 16,
    color: '#666',
  },
  timer: {
    textAlign: 'center',
    marginBottom: 20,
    fontSize: 18,
    fontWeight: 'bold',
    color: '#007AFF',
  },
  input: {
    height: 50,
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    paddingHorizontal: 15,
    marginBottom: 15,
    fontSize: 24,
    textAlign: 'center',
    letterSpacing: 8,
  },
  button: {
    backgroundColor: '#007AFF',
    height: 50,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: 10,
  },
  disabledButton: {
    backgroundColor: '#ccc',
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  error: {
    color: 'red',
    marginBottom: 15,
    textAlign: 'center',
  },
  resendButton: {
    marginTop: 15,
    alignItems: 'center',
  },
  resendButtonText: {
    color: '#007AFF',
    fontSize: 14,
  },
});

export default MFAVerificationScreen;