import { create } from 'zustand';
import { getApiUrl } from '../api/client';

export interface AuthUser {
  id: string;
  name: string;
  email: string;
  created_at?: string;
}

interface AuthState {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (token: string, user: AuthUser) => void;
  logout: () => void;
  checkAuth: () => Promise<boolean>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  token: localStorage.getItem('sms_auth_token'),
  isAuthenticated: Boolean(localStorage.getItem('sms_auth_token')),
  isLoading: true,

  login: (token: string, user: AuthUser) => {
    localStorage.setItem('sms_auth_token', token);
    set({ token, user, isAuthenticated: true, isLoading: false });
  },

  logout: () => {
    localStorage.removeItem('sms_auth_token');
    set({ token: null, user: null, isAuthenticated: false, isLoading: false });
  },

  checkAuth: async () => {
    const token = localStorage.getItem('sms_auth_token');
    if (!token) {
      set({ user: null, token: null, isAuthenticated: false, isLoading: false });
      return false;
    }

    try {
      const res = await fetch(getApiUrl('/api/v1/auth/me'), {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (res.ok) {
        const user = await res.json();
        set({ user, token, isAuthenticated: true, isLoading: false });
        return true;
      } else {
        localStorage.removeItem('sms_auth_token');
        set({ user: null, token: null, isAuthenticated: false, isLoading: false });
        return false;
      }
    } catch (err) {
      set({ isLoading: false });
      return get().isAuthenticated;
    }
  },
}));
