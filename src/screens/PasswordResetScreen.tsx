import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  Alert,
} from 'react-native';
import ReCAPTCHA from 'react-native-recaptcha-that-works';
import { useNavigation } from '@react-navigation/native';
import { validatePassword } from '../utils/validation';
import { resetPassword } from '../services/auth';
import { logPasswordResetActivity } from '../utils/logging';

const PasswordResetScreen: React.FC = () => {
  const navigation = useNavigation();
  const [formData, setFormData] = useState({
    email: '',
    newPassword: '',
    confirmPassword: '',
    resetCode: '',
  });
  const [errors, setErrors] = useState({
    email: '',
    newPassword: '',
    confirmPassword: '',
    resetCode: '',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isCaptchaVerified, setIsCaptchaVerified] = useState(false);
  const [step, setStep] = useState(1); // 1: Enter email, 2: Enter reset code and new password

  const validateForm = () => {
    let isValid = true;
    const newErrors = { ...errors };

    if (step === 1) {
      if (!formData.email.trim()) {
        newErrors.email = 'Email is required';
        isValid = false;
      } else {
        newErrors.email = '';
      }
    } else {
      // Reset code validation
      if (!formData.resetCode.trim()) {
        newErrors.resetCode = 'Reset code is required';
        isValid = false;
      } else {
        newErrors.resetCode = '';
      }

      // Password validation
      if (!validatePassword(formData.newPassword)) {
        newErrors.newPassword = 'Password must be at least 8 characters long and contain uppercase, lowercase, number, and special character';
        isValid = false;
      } else {
        newErrors.newPassword = '';
      }

      // Confirm password validation
      if (formData.newPassword !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match';
        isValid = false;
      } else {
        newErrors.confirmPassword = '';
      }
    }

    setErrors(newErrors);
    return isValid;
  };

  const handleRequestReset = async () => {
    if (!isCaptchaVerified) {
      Alert.alert('Error', 'Please complete the CAPTCHA verification');
      return;
    }

    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    try {
      // Request password reset email
      await resetPassword.requestReset(formData.email);
      
      // Log reset request activity
      await logPasswordResetActivity({
        email: formData.email,
        action: 'RESET_REQUEST',
        status: 'SUCCESS',
        timestamp: new Date(),
      });

      Alert.alert(
        'Reset Code Sent',
        'Please check your email for the password reset code.',
        [{ text: 'OK' }]
      );
      setStep(2);
    } catch (error) {
      Alert.alert('Reset Request Failed', error.message);
      await logPasswordResetActivity({
        email: formData.email,
        action: 'RESET_REQUEST',
        status: 'FAILED',
        error: error.message,
        timestamp: new Date(),
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPassword = async () => {
    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    try {
      // Reset password
      await resetPassword.confirmReset(formData.email, formData.resetCode, formData.newPassword);
      
      // Log reset completion activity
      await logPasswordResetActivity({
        email: formData.email,
        action: 'RESET_COMPLETE',
        status: 'SUCCESS',
        timestamp: new Date(),
      });

      Alert.alert(
        'Password Reset Successful',
        'You can now login with your new password.',
        [
          {
            text: 'OK',
            onPress: () => navigation.navigate('Login'),
          },
        ]
      );
    } catch (error) {
      Alert.alert('Password Reset Failed', error.message);
      await logPasswordResetActivity({
        email: formData.email,
        action: 'RESET_COMPLETE',
        status: 'FAILED',
        error: error.message,
        timestamp: new Date(),
      });
    } finally {
      setIsLoading(false);
    }
  };

  const onCaptchaVerify = (token: string) => {
    setIsCaptchaVerified(true);
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.formContainer}>
        <Text style={styles.title}>Reset Password</Text>

        {step === 1 ? (
          <>
            <TextInput
              style={styles.input}
              placeholder="Email"
              keyboardType="email-address"
              autoCapitalize="none"
              value={formData.email}
              onChangeText={(text) => setFormData({ ...formData, email: text })}
            />
            {errors.email ? <Text style={styles.errorText}>{errors.email}</Text> : null}

            <ReCAPTCHA
              siteKey="your-recaptcha-site-key"
              onVerify={onCaptchaVerify}
              size="normal"
            />

            <TouchableOpacity
              style={[styles.button, isLoading && styles.buttonDisabled]}
              onPress={handleRequestReset}
              disabled={isLoading}
            >
              <Text style={styles.buttonText}>
                {isLoading ? 'Sending...' : 'Send Reset Code'}
              </Text>
            </TouchableOpacity>
          </>
        ) : (
          <>
            <TextInput
              style={styles.input}
              placeholder="Reset Code"
              value={formData.resetCode}
              onChangeText={(text) => setFormData({ ...formData, resetCode: text })}
            />
            {errors.resetCode ? <Text style={styles.errorText}>{errors.resetCode}</Text> : null}

            <TextInput
              style={styles.input}
              placeholder="New Password"
              secureTextEntry
              value={formData.newPassword}
              onChangeText={(text) => setFormData({ ...formData, newPassword: text })}
            />
            {errors.newPassword ? <Text style={styles.errorText}>{errors.newPassword}</Text> : null}

            <TextInput
              style={styles.input}
              placeholder="Confirm New Password"
              secureTextEntry
              value={formData.confirmPassword}
              onChangeText={(text) => setFormData({ ...formData, confirmPassword: text })}
            />
            {errors.confirmPassword ? <Text style={styles.errorText}>{errors.confirmPassword}</Text> : null}

            <TouchableOpacity
              style={[styles.button, isLoading && styles.buttonDisabled]}
              onPress={handleResetPassword}
              disabled={isLoading}
            >
              <Text style={styles.buttonText}>
                {isLoading ? 'Resetting...' : 'Reset Password'}
              </Text>
            </TouchableOpacity>
          </>
        )}

        <TouchableOpacity
          style={styles.linkButton}
          onPress={() => navigation.navigate('Login')}
        >
          <Text style={styles.linkText}>Back to Login</Text>
        </TouchableOpacity>
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
  },
  formContainer: {
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
    textAlign: 'center',
  },
  input: {
    height: 50,
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 8,
    paddingHorizontal: 15,
    marginBottom: 10,
    fontSize: 16,
  },
  errorText: {
    color: 'red',
    fontSize: 12,
    marginBottom: 10,
  },
  button: {
    backgroundColor: '#007AFF',
    height: 50,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
    marginTop: 20,
  },
  buttonDisabled: {
    opacity: 0.7,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  linkButton: {
    marginTop: 15,
    alignItems: 'center',
  },
  linkText: {
    color: '#007AFF',
    fontSize: 16,
  },
});

export default PasswordResetScreen;