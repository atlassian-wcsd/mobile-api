import axios from 'axios';
import { API_BASE_URL } from '../config/constants';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000, // 10 seconds timeout
});

// User registration API
export const registerUser = async (userData) => {
  try {
    const { name, email, password, phoneNumber, captchaToken } = userData;
    
    // Input validation
    if (!name || !email || !password || !phoneNumber) {
      throw new Error('All fields are required');
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      throw new Error('Invalid email format');
    }

    // Password strength validation
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }

    // Phone number format validation
    const phoneRegex = /^\+?[\d\s-]{10,}$/;
    if (!phoneRegex.test(phoneNumber)) {
      throw new Error('Invalid phone number format');
    }

    const response = await api.post('/auth/register', {
      name,
      email,
      password,
      phoneNumber,
      captchaToken,
    });

    return {
      success: true,
      data: response.data,
      message: 'Registration successful. Please check your email for verification.',
    };
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.message || error.message,
    };
  }
};

// Email verification API
export const verifyEmail = async (token) => {
  try {
    const response = await api.post('/auth/verify-email', { token });
    return {
      success: true,
      data: response.data,
      message: 'Email verification successful',
    };
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.message || error.message,
    };
  }
};

// Request new verification email
export const resendVerificationEmail = async (email) => {
  try {
    const response = await api.post('/auth/resend-verification', { email });
    return {
      success: true,
      message: 'Verification email sent successfully',
    };
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.message || error.message,
    };
  }
};

// Add request interceptor for authentication
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle network errors
    if (!error.response) {
      return Promise.reject({
        message: 'Network error. Please check your internet connection.',
      });
    }

    // Handle specific HTTP status codes
    switch (error.response.status) {
      case 400:
        return Promise.reject({
          message: 'Invalid request. Please check your input.',
        });
      case 401:
        // Handle unauthorized access
        localStorage.removeItem('authToken');
        return Promise.reject({
          message: 'Unauthorized access. Please login again.',
        });
      case 429:
        return Promise.reject({
          message: 'Too many requests. Please try again later.',
        });
      default:
        return Promise.reject(error.response.data);
    }
  }
);

export default api;