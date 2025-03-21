import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../models/User';
import { AuthenticationService } from '../services/AuthenticationService';

interface AuthContextType {
    user: User | null;
    loading: boolean;
    error: string | null;
    login: (email: string, password: string) => Promise<void>;
    logout: () => Promise<void>;
    initiatePasswordReset: (email: string) => Promise<void>;
    completePasswordReset: (token: string, newPassword: string) => Promise<void>;
    clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
}

interface AuthProviderProps {
    children: React.ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
    const [user, setUser] = useState<User | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const authService = new AuthenticationService();

    useEffect(() => {
        // Check for existing session on mount
        const checkSession = async () => {
            try {
                // Implementation would check for existing session
                // and set user if session exists
                setLoading(false);
            } catch (error) {
                setError('Failed to restore session');
                setLoading(false);
            }
        };

        checkSession();
    }, []);

    const login = async (email: string, password: string) => {
        try {
            setLoading(true);
            setError(null);
            const authenticatedUser = await authService.login(email, password);
            setUser(authenticatedUser);
        } catch (error) {
            setError(error instanceof Error ? error.message : 'An error occurred during login');
            throw error;
        } finally {
            setLoading(false);
        }
    };

    const logout = async () => {
        try {
            setLoading(true);
            setError(null);
            if (user) {
                await authService.logout(user.id);
                setUser(null);
            }
        } catch (error) {
            setError(error instanceof Error ? error.message : 'An error occurred during logout');
            throw error;
        } finally {
            setLoading(false);
        }
    };

    const initiatePasswordReset = async (email: string) => {
        try {
            setLoading(true);
            setError(null);
            await authService.initiatePasswordReset(email);
        } catch (error) {
            setError(error instanceof Error ? error.message : 'Failed to initiate password reset');
            throw error;
        } finally {
            setLoading(false);
        }
    };

    const completePasswordReset = async (token: string, newPassword: string) => {
        try {
            setLoading(true);
            setError(null);
            await authService.completePasswordReset(token, newPassword);
        } catch (error) {
            setError(error instanceof Error ? error.message : 'Failed to complete password reset');
            throw error;
        } finally {
            setLoading(false);
        }
    };

    const clearError = () => {
        setError(null);
    };

    const value = {
        user,
        loading,
        error,
        login,
        logout,
        initiatePasswordReset,
        completePasswordReset,
        clearError
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
}