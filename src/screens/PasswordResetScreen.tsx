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
import { resetPassword, verifyResetToken } from '../services/auth';
import { SecurityLogger } from '../utils/securityLogger';

const securityLogger = new SecurityLogger();

const PasswordResetScreen: React.FC = () => {
  const navigation = useNavigation();
  const [email, setEmail] = useState('');
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showResetForm, setShowResetForm] = useState(false);
  const [error, setError] = useState('');

  const handleRequestReset = async () => {
    try {
      setError('');

      if (!validateEmail(email)) {
        throw new Error('Please enter a valid email address');
      }

      // Request password reset token
      await resetPassword(email);
      
      securityLogger.logSuccess('password_reset_requested', { email });
      setShowResetForm(true);
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred while requesting password reset';
      setError(errorMessage);
      securityLogger.logFailure('password_reset_request', { email, error: errorMessage });
    }
  };

  const handleResetPassword = async () => {
    try {
      setError('');

      if (!resetToken || resetToken.length !== 6) {
        throw new Error('Please enter a valid reset code');
      }

      if (!validatePassword(newPassword)) {
        throw new Error('Password must be at least 8 characters long and contain numbers, letters, and special characters');
      }

      if (newPassword !== confirmPassword) {
        throw new Error('Passwords do not match');
      }

      // Verify token and set new password
      const result = await verifyResetToken(email, resetToken, newPassword);

      if (result.success) {
        securityLogger.logSuccess('password_reset_complete', { email });
        Alert.alert(
          'Success',
          'Your password has been reset successfully. Please login with your new password.',
          [{ text: 'OK', onPress: () => navigation.navigate('Login') }]
        );
      } else {
        throw new Error('Invalid or expired reset code');
      }

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'An error occurred while resetting password';
      setError(errorMessage);
      securityLogger.logFailure('password_reset', { email, error: errorMessage });
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Reset Password</Text>
      
      {error ? <Text style={styles.error}>{error}</Text> : null}

      {!showResetForm ? (
        <>
          <Text style={styles.instructions}>
            Enter your email address to receive a password reset code
          </Text>

          <TextInput
            style={styles.input}
            placeholder="Email"
            value={email}
            onChangeText={setEmail}
            keyboardType="email-address"
            autoCapitalize="none"
          />

          <TouchableOpacity
            style={styles.button}
            onPress={handleRequestReset}
          >
            <Text style={styles.buttonText}>Send Reset Code</Text>
          </TouchableOpacity>
        </>
      ) : (
        <>
          <Text style={styles.instructions}>
            Enter the reset code sent to your email and your new password
          </Text>

          <TextInput
            style={styles.input}
            placeholder="Reset Code"
            value={resetToken}
            onChangeText={setResetToken}
            keyboardType="number-pad"
            maxLength={6}
          />

          <TextInput
            style={styles.input}
            placeholder="New Password"
            value={newPassword}
            onChangeText={setNewPassword}
            secureTextEntry
          />

          <TextInput
            style={styles.input}
            placeholder="Confirm New Password"
            value={confirmPassword}
            onChangeText={setConfirmPassword}
            secureTextEntry
          />

          <TouchableOpacity
            style={styles.button}
            onPress={handleResetPassword}
          >
            <Text style={styles.buttonText}>Reset Password</Text>
          </TouchableOpacity>
        </>
      )}

      <TouchableOpacity
        style={styles.backButton}
        onPress={() => navigation.navigate('Login')}
      >
        <Text style={styles.backButtonText}>Back to Login</Text>
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
    marginBottom: 30,
    textAlign: 'center',
  },
  instructions: {
    textAlign: 'center',
    marginBottom: 20,
    fontSize: 14,
    color: '#666',
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
  backButton: {
    marginTop: 15,
    alignItems: 'center',
  },
  backButtonText: {
    color: '#007AFF',
    fontSize: 14,
  },
});

export default PasswordResetScreen;