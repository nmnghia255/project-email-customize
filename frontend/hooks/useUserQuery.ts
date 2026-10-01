// ========================================
// useUserQuery Hook
// ========================================
// Fetch and initialize user session
// ========================================

import { useEffect } from 'react';
import { useAuth } from '@/contexts/auth-context';
import { getCurrentUser } from '@/lib/auth';
import { setGlobalAccessToken } from '@/lib/api';
import { clearTokens } from '@/lib/token';
import { AutoIndexService } from '@/lib/auto-index';

/**
 * Hook để initialize và maintain user session
 * Tự động chạy khi app mount
 * 
 * NEW SECURE STRATEGY:
 * - Access token: In-memory only (AuthContext + window.__accessToken)
 * - Refresh token: HttpOnly cookie only (sent automatically)
 * 
 * Logic:
 * 1. Kiểm tra có accessToken trong AuthContext không
 * 2. Nếu có: Fetch user profile
 * 3. Nếu không có: Gọi /auth/refresh (refreshToken tự động gửi qua cookie)
 * 4. Nếu refresh thành công: Lưu accessToken và fetch user profile
 * 5. Nếu refresh thất bại: Set unauthenticated
 */
export const useUserQuery = () => {
  const { setUser, setIsAuthenticated, setIsLoading, setAccessToken, accessToken, isLoading } = useAuth();

  useEffect(() => {
    const initializeAuth = async () => {
      if (accessToken) {
        // Ensure window.__accessToken is also set for non-axios requests
        setGlobalAccessToken(accessToken);
        
        try {
          const userProfile = await getCurrentUser();
          setUser(userProfile);
          setIsAuthenticated(true);
          
          // Auto-index emails for semantic search (background, non-blocking)
          AutoIndexService.autoIndex(userProfile.id, accessToken, 200).catch(() => {});
          
        } catch (fetchError: any) {
          // Access token might be expired, clear it and try refresh
          setAccessToken(null);
          setGlobalAccessToken(null);
        } finally {
          setIsLoading(false);
        }
        return;
      }
      
      // No accessToken → try refresh from HttpOnly cookie
      if (!accessToken) {
        try {
          const backendUrl = process.env.NEXT_PUBLIC_BACKEND_API_URL || 'http://localhost:5000';
          const refreshResponse = await fetch(`${backendUrl}/auth/refresh`, {
            method: 'POST',
            credentials: 'include',  // 🔒 Send HttpOnly cookie automatically
            headers: { 'Content-Type': 'application/json' }
          });
          
          if (refreshResponse.ok) {
            const { accessToken: newAccessToken } = await refreshResponse.json();
            
            // Store new access token in-memory
            setAccessToken(newAccessToken);  // AuthContext
            setGlobalAccessToken(newAccessToken);  // window.__accessToken for axios
            
            // Fetch user profile with new token
            const userProfile = await getCurrentUser();
            setUser(userProfile);
            setIsAuthenticated(true);
            
            // Auto-index emails for semantic search (background, non-blocking)
            AutoIndexService.autoIndex(userProfile.id, newAccessToken, 200).catch(() => {});
          } else {
            clearTokens();
            setUser(null);
            setIsAuthenticated(false);
          }
        } catch (error) {
          clearTokens();
          setUser(null);
          setIsAuthenticated(false);
        } finally {
          setIsLoading(false);
        }
      }
    };

    initializeAuth();
    // Re-run when accessToken changes (e.g., after login/refresh)
    // Also runs on mount to check for existing session
  }, [accessToken]); // Keep only accessToken to avoid infinite loops

  return { isLoading };
};
