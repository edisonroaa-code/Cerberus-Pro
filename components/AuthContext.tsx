import React, { useState, useEffect, useRef } from 'react';
import { AlertCircle, LogOut, Settings, Shield, Key, Lock } from 'lucide-react';
import { API_BASE_URL } from '../services/apiConfig';
import { checkBackendReady } from '../services/backendHealth';

export interface AuthState {
  isAuthenticated: boolean;
  user: User | null;
  accessToken: string | null;
}

export interface User {
  id: string;
  username: string;
  email: string;
  full_name?: string;
  role: string;
  created_at?: string;
  last_login?: string | null;
  mfa_enabled?: boolean;
  permissions?: string[];
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

const AuthContext = React.createContext<any>(null);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [authState, setAuthState] = useState<AuthState>({
    isAuthenticated: false,
    user: null,
    accessToken: null,
  });

  const [loading, setLoading] = useState(true);
  const refreshPromiseRef = useRef<Promise<boolean> | null>(null);

  useEffect(() => {
    void checkSession();
  }, []);

  const checkSession = async () => {
    try {
      const backendReady = await checkBackendReady({ apiBaseUrl: API_BASE_URL });
      if (!backendReady) {
        setAuthState({ isAuthenticated: false, user: null, accessToken: null });
        return;
      }
      const response = await fetch(`${API_BASE_URL}/auth/me`, {
        credentials: 'include',
      });
      if (!response.ok) {
        setAuthState({ isAuthenticated: false, user: null, accessToken: null });
        return;
      }
      const userData = await response.json();
      setAuthState((prev) => ({
        ...prev,
        isAuthenticated: true,
        user: userData,
      }));
    } catch {
      setAuthState({ isAuthenticated: false, user: null, accessToken: null });
    } finally {
      setLoading(false);
    }
  };

  const refreshAccessToken = async (): Promise<boolean> => {
    if (refreshPromiseRef.current) {
      return refreshPromiseRef.current;
    }
    refreshPromiseRef.current = (async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
        });
        if (!response.ok) {
          setAuthState({ isAuthenticated: false, user: null, accessToken: null });
          return false;
        }
        const tokens: TokenResponse = await response.json();
        setAuthState((prev) => ({
          ...prev,
          isAuthenticated: true,
          accessToken: tokens.access_token,
        }));
        await checkSession();
        return true;
      } catch {
        setAuthState({ isAuthenticated: false, user: null, accessToken: null });
        return false;
      } finally {
        refreshPromiseRef.current = null;
      }
    })();
    return refreshPromiseRef.current;
  };

  const authFetch = async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const mergedInit: RequestInit = {
      ...init,
      credentials: 'include',
      headers: {
        ...(init.headers || {}),
      },
    };

    if (authState.accessToken) {
      (mergedInit.headers as Record<string, string>)['Authorization'] = `Bearer ${authState.accessToken}`;
    }

    let response = await fetch(input, mergedInit);
    if (response.status !== 401) {
      return response;
    }

    const refreshed = await refreshAccessToken();
    if (!refreshed) {
      return response;
    }

    const retryInit: RequestInit = {
      ...mergedInit,
      headers: {
        ...(mergedInit.headers || {}),
      },
    };
    if (authState.accessToken) {
      (retryInit.headers as Record<string, string>)['Authorization'] = `Bearer ${authState.accessToken}`;
    }
    response = await fetch(input, retryInit);
    return response;
  };

  const login = async (username: string, password: string, mfaCode?: string): Promise<'success' | 'mfa_required' | 'error'> => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password, mfa_code: mfaCode }),
      });

      if (response.status === 403) {
        const body = await response.text();
        if (body.includes('MFA') || body.includes('mfa')) {
          return 'mfa_required';
        }
      }

      if (!response.ok) {
        throw new Error(await response.text());
      }

      const tokens: TokenResponse = await response.json();
      await checkSession();
      setAuthState((prev) => ({
        ...prev,
        isAuthenticated: true,
        accessToken: tokens.access_token,
      }));
      return 'success';
    } catch (error) {
      console.error('Login failed:', error);
      return 'error';
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData: any) => {
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(userData),
      });

      if (!response.ok) {
        throw new Error(await response.text());
      }

      return true;
    } catch (error) {
      console.error('Registration failed:', error);
      return false;
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      await fetch(`${API_BASE_URL}/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch (error) {
      console.error('Logout request failed:', error);
    }

    setAuthState({ isAuthenticated: false, user: null, accessToken: null });
  };

  const hasPermission = (permission: string): boolean => {
    return authState.user?.permissions?.includes(permission) ?? false;
  };

  const hasRole = (role: string | string[]): boolean => {
    if (!authState.user) return false;
    const roles = Array.isArray(role) ? role : [role];
    return roles.includes(authState.user.role);
  };

  const value = {
    authState,
    loading,
    login,
    register,
    logout,
    hasPermission,
    hasRole,
    refreshAccessToken,
    authFetch,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [error, setError] = useState('');
  const [needsMFA, setNeedsMFA] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    const result = await login(username, password, mfaCode || undefined);

    if (result === 'mfa_required') {
      setNeedsMFA(true);
      setError('Se requiere código MFA para esta cuenta');
    } else if (result === 'error') {
      setError('Credenciales inválidas o código MFA incorrecto');
    }
    // 'success' — AuthProvider will update isAuthenticated automatically

    setIsLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-12 h-12 text-cyan-500" />
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Cerberus Pro</h1>
          <p className="text-gray-400">Enterprise Security Edition</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div className="bg-red-900/20 border border-red-500 text-red-200 px-4 py-3 rounded flex items-center gap-2">
              <AlertCircle className="w-4 h-4" />
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              placeholder="Enter username"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
              placeholder="Enter password"
              required
            />
          </div>

          {needsMFA && (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">MFA Code</label>
              <input
                type="text"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                className="w-full px-4 py-2 bg-gray-800 border border-gray-700 rounded text-white placeholder-gray-500 focus:outline-none focus:border-cyan-500"
                placeholder="6-digit code"
                maxLength={6}
              />
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="w-full bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-600 text-white font-semibold py-2 rounded transition"
          >
            {isLoading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>

        <div className="mt-8 pt-8 border-t border-gray-700 space-y-3">
          <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-500" />
            Security Features
          </h3>
          <ul className="text-xs text-gray-400 space-y-2">
            <li className="flex items-center gap-2"><span className="w-1 h-1 bg-cyan-500 rounded-full" />Enterprise-grade JWT authentication</li>
            <li className="flex items-center gap-2"><span className="w-1 h-1 bg-cyan-500 rounded-full" />Multi-factor authentication (MFA/2FA)</li>
            <li className="flex items-center gap-2"><span className="w-1 h-1 bg-cyan-500 rounded-full" />Role-based access control (RBAC)</li>
            <li className="flex items-center gap-2"><span className="w-1 h-1 bg-cyan-500 rounded-full" />Complete audit trail logging</li>
            <li className="flex items-center gap-2"><span className="w-1 h-1 bg-cyan-500 rounded-full" />TLS 1.3 encryption</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export const ProtectedRoute: React.FC<{
  children: React.ReactNode;
  requiredRole?: string | string[];
  requiredPermission?: string;
}> = ({ children, requiredRole, requiredPermission }) => {
  const { authState, hasRole, hasPermission } = useAuth();

  if (!authState.isAuthenticated) {
    return <LoginPage />;
  }

  if (requiredRole && !hasRole(requiredRole)) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">Access Denied</h1>
          <p className="text-gray-400">You do not have the required role</p>
        </div>
      </div>
    );
  }

  if (requiredPermission && !hasPermission(requiredPermission)) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center">
          <Lock className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">Permission Denied</h1>
          <p className="text-gray-400">You do not have permission for this action</p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};

export const UserMenu: React.FC = () => {
  const { authState, logout } = useAuth();
  const [open, setOpen] = useState(false);

  if (!authState.user) return null;

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-white rounded transition"
      >
        <Shield className="w-4 h-4" />
        {authState.user.username}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-48 bg-gray-800 border border-gray-700 rounded shadow-lg z-50">
          <div className="px-4 py-3 border-b border-gray-700">
            <p className="text-sm text-white font-semibold">{authState.user.full_name || authState.user.username}</p>
            <p className="text-xs text-gray-400">{authState.user.email}</p>
            <p className="text-xs text-cyan-400 mt-1 uppercase">{authState.user.role}</p>
          </div>

          <span className="block px-4 py-2 text-sm text-gray-500 flex items-center gap-2 cursor-not-allowed" title="Coming soon">
            <Settings className="w-4 h-4" />
            Settings
          </span>

          <span className="block px-4 py-2 text-sm text-gray-500 flex items-center gap-2 cursor-not-allowed" title="Coming soon">
            <Key className="w-4 h-4" />
            API Keys
          </span>

          <button
            onClick={logout}
            className="w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-gray-700 flex items-center gap-2"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      )}
    </div>
  );
};
