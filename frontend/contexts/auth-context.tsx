"use client";

// ========================================
// AUTH CONTEXT - IN-MEMORY TOKEN STORAGE
// ========================================
// SECURITY STRATEGY:
// - Access Token: In-memory ONLY (not persisted)
// - Refresh Token: HttpOnly cookie ONLY (server-side)
// - User data: localStorage (for UX only, not sensitive)
// 
// Benefits:
// ✅ Access token immune to XSS (not in localStorage/cookies)
// ✅ Refresh token immune to XSS (HttpOnly cookie)
// ✅ CSRF protection via SameSite cookie attribute
// ========================================

import React, { createContext, useContext, useState, ReactNode, useEffect } from 'react';
import api from '@/lib/api';
import { User } from '@/types/auth.types';
import { getUserData, saveUserData, clearUserData } from '@/lib/token';

// Decode JWT to get expiration time
const decodeJWT = (token: string): { exp?: number } | null => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error('[AuthContext] Failed to decode JWT:', error);
    return null;
  }
};

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isAuthInitialized: boolean;  // 🔒 New: tracks if auth check is complete
  accessToken: string | null;  // 🔒 IN-MEMORY ONLY
  setUser: (user: User | null) => void;
  setIsAuthenticated: (value: boolean) => void;
  setIsLoading: (value: boolean) => void;
  setAccessToken: (token: string | null) => void;  // 🔒 IN-MEMORY ONLY
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUserState] = useState<User | null>(null);
  const [isAuthenticated, setIsAuthenticatedState] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthInitialized, setIsAuthInitialized] = useState(false);  // 🔒 New flag
  const [accessToken, setAccessToken] = useState<string | null>(null);  // 🔒 IN-MEMORY
  const [hasSyncedOnLogin, setHasSyncedOnLogin] = useState(false); // prevent repeated syncs

  // Wrapper for setIsAuthenticated to persist state
  const setIsAuthenticated = (value: boolean) => {
    setIsAuthenticatedState(value);
    if (typeof window !== 'undefined') {
      if (value) {
        localStorage.setItem('isAuthenticated', 'true');
      } else {
        localStorage.removeItem('isAuthenticated');
        // reset per-session sync guard on logout
        setHasSyncedOnLogin(false);
      }
    }
  };

  // Wrapper cho setUser để tự động lưu vào localStorage (chỉ user data, không có tokens)
  const setUser = (userData: User | null) => {
    setUserState(userData);
    if (userData) {
      saveUserData(userData);
    } else {
      clearUserData();
    }
  };

  // Restore user data AND auth state từ localStorage khi component mount
  // NOTE: Không restore token - token phải được refresh từ HttpOnly cookie
  useEffect(() => {
    const savedUser = getUserData();
    const savedAuthState = localStorage.getItem('isAuthenticated') === 'true';
    
    if (savedUser && savedAuthState) {
      setUserState(savedUser);
      setIsAuthenticatedState(true);
      // Auth state restored - useUserQuery will validate and refresh token if needed
    }
  }, []);

  // Listen for token refresh events from api.ts interceptor
  useEffect(() => {
    const handleTokenRefresh = (event: CustomEvent) => {
      const { accessToken: newToken } = event.detail;
      setAccessToken(newToken);
    };

    window.addEventListener('tokenRefreshed', handleTokenRefresh as EventListener);
    
    return () => {
      window.removeEventListener('tokenRefreshed', handleTokenRefresh as EventListener);
    };
  }, []);

  // Sync window.__accessToken whenever AuthContext accessToken changes
  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.__accessToken = accessToken;
    }
  }, [accessToken]);

  // Set isAuthInitialized when loading completes
  useEffect(() => {
    if (!isLoading && !isAuthInitialized) {
      setIsAuthInitialized(true);
    }
  }, [isLoading, isAuthInitialized]);

  // Auto-refresh token based on JWT expiration
  useEffect(() => {
    if (!isAuthenticated || !accessToken) return;

    // Decode JWT to get expiration time
    const decoded = decodeJWT(accessToken);
    if (!decoded || !decoded.exp) {
      return;
    }

    const expiresAt = decoded.exp * 1000; // Convert to milliseconds
    const now = Date.now();
    const timeUntilExpiry = expiresAt - now;
    
    // Refresh 1 minute before expiration (or immediately if already expired)
    const refreshBuffer = 60 * 1000; // 1 minute
    const refreshIn = Math.max(0, timeUntilExpiry - refreshBuffer);

    const refreshTimeout = setTimeout(async () => {
      try {
        const backendUrl = process.env.NEXT_PUBLIC_BACKEND_API_URL || 'http://localhost:5000';
        const response = await fetch(`${backendUrl}/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' }
        });

        if (response.ok) {
          const { accessToken: newToken } = await response.json();
          setAccessToken(newToken);
          if (typeof window !== 'undefined') {
            window.__accessToken = newToken;
          }
        } else {
          setIsAuthenticated(false);
          setAccessToken(null);
          setUser(null);
        }
      } catch (error) {
        // Silently handle refresh error
      }
    }, refreshIn);

    return () => {
      clearTimeout(refreshTimeout);
    };
  }, [isAuthenticated, accessToken]);

  // Auto-sync Gmail emails after login using axios `api` client
  useEffect(() => {
    if (isAuthenticated && user && !hasSyncedOnLogin) {
      const key = `lastLoginSync_${user.id}`;
      const lastTs = typeof window !== 'undefined' ? parseInt(localStorage.getItem(key) || '0', 10) : 0;
      const now = Date.now();
      const FIVE_MIN = 5 * 60 * 1000;

      if (now - lastTs < FIVE_MIN) {
        setHasSyncedOnLogin(true); // treat as already triggered for this session
        return;
      }

      const syncEmails = async () => {
        try {
          // Use the app axios client so cookies and interceptor are used
          await api.post('/sync/gmail', { limit: 100, forceResync: true });
          // Mark as synced so we don't trigger again in this session
          setHasSyncedOnLogin(true);
          if (typeof window !== 'undefined') {
            localStorage.setItem(key, String(Date.now()));
          }
        } catch (err: any) {
          // Sync failed silently
        }
      };

      // Fire-and-forget but attempt once on login (with persistence to avoid repeats on reload)
      syncEmails();
    }
  }, [isAuthenticated, user, hasSyncedOnLogin]);

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated,
        isLoading,
        isAuthInitialized,
        accessToken,
        setUser,
        setIsAuthenticated,
        setIsLoading,
        setAccessToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// ========================================
// useAuth Hook
// ========================================
// Access auth state từ bất kỳ component nào

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
