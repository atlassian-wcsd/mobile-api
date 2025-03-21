import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { validatePassword, validateEmail } from '../utils/validation';
import { login, requestMFA, verifyMFA } from '../services/auth';
import { RateLimiter } from '../utils/rateLimiter';
import { SecurityLogger } from '../utils/securityLogger';

const rateLimiter = new RateLimiter(3, 300000); // 3 attempts per 5 minutes
const securityLogger = new SecurityLogger();

const LoginScreen: React.FC = () => {
  const navigation = useNavigation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMFACode] = useState('');
  const [showMFA, setShowMFA] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async () => {
    try {
      // Reset error state
      setError('');

      // Check rate limiting
      if (!rateLimiter.tryRequest()) {
        throw new Error('Too many login attempts. Please try again later.');
      }

      // Validate inputs
      if (!validateEmail(email)) {
        throw new Error('Please enter a valid email address');
      }

      if (!validatePassword(password)) {
        throw new Error('Password must be at least 8 characters long and contain numbers, letters, and special characters');
      }

      // Attempt login
      const loginResult = await login(email, password);

      // If MFA is required
      if (loginResult.requiresMFA) {
        await requestMFA(email);
        setShowMFA(true);
        return;
      }

      // Log successful login
      securityLogger.logSuccess('login', { email });

      // Navigate to home screen
      navigation.navigate('Home');

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred during login';
      setError(errorMessage);
      securityLogger.logFailure('login', { email, error: errorMessage });
    }
  };

  const handleMFASubmit = async () => {
    try {
      setError('');
      
      if (!mfaCode || mfaCode.length !== 6) {
        throw new Error('Please enter a valid 6-digit MFA code');
      }

      const verificationResult = await verifyMFA(email, mfaCode);
      
      if (verificationResult.success) {
        securityLogger.logSuccess('mfa_verification', { email });
        navigation.navigate('Home');
      } else {
        throw new Error('Invalid MFA code');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred during MFA verification';
      setError(errorMessage);
      securityLogger.logFailure('mfa_verification', { email, error: errorMessage });
    }
  };

  const handleForgotPassword = () => {
    navigation.navigate('ForgotPassword');
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Login</Text>
      
      {error ? <Text style={styles.error}>{error}</Text> : null}

      {!showMFA ? (
        <>
          <TextInput
            style={styles.input}
            placeholder="Email"
            value={email}
            onChangeText={setEmail}
            keyboardType="email-address"
            autoCapitalize="none"
          />
          
          <TextInput
            style={styles.input}
            placeholder="Password"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
          />

          <TouchableOpacity
            style={styles.button}
            onPress={handleLogin}
          >
            <Text style={styles.buttonText}>Login</Text>
          </TouchableOpacity>

          <TouchableOpacity
            onPress={handleForgotPassword}
            style={styles.forgotPassword}
          >
            <Text style={styles.forgotPasswordText}>Forgot Password?</Text>
          </TouchableOpacity>
        </>
      ) : (
        <>
          <Text style={styles.mfaText}>
            Please enter the verification code sent to your email
          </Text>
          
          <TextInput
            style={styles.input}
            placeholder="Enter 6-digit code"
            value={mfaCode}
            onChangeText={setMFACode}
            keyboardType="number-pad"
            maxLength={6}
          />

          <TouchableOpacity
            style={styles.button}
            onPress={handleMFASubmit}
          >
            <Text style={styles.buttonText}>Verify</Text>
          </TouchableOpacity>
        </>
      )}
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
    marginBottom: 30,
    textAlign: 'center',
  },
  input: {
    height: 50,
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    paddingHorizontal: 15,
    marginBottom: 15,
    fontSize: 16,
  },
  button: {
    backgroundColor: '#007AFF',
    height: 50,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: 10,
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
  forgotPassword: {
    marginTop: 15,
    alignItems: 'center',
  },
  forgotPasswordText: {
    color: '#007AFF',
    fontSize: 14,
  },
  mfaText: {
    textAlign: 'center',
    marginBottom: 20,
    fontSize: 14,
    color: '#666',
  },
});

export default LoginScreen;