import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Lock, Mail, ArrowRight, AlertCircle, CheckCircle, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { useAuthStore } from '../store/useAuthStore';
import { getApiUrl } from '../api/client';
import { Logo } from '../components/common/Logo';
import { AuthHero } from '../components/auth/AuthHero';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuthStore();

  const successMessage = (location.state as any)?.successMessage as string | undefined;
  const registeredEmail = (location.state as any)?.registeredEmail as string | undefined;

  const [email, setEmail] = useState(registeredEmail || '');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (registeredEmail && !email) {
      setEmail(registeredEmail);
    }
  }, [registeredEmail]);

  const fromPath = (location.state as any)?.from?.pathname || '/dashboard';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const res = await fetch(getApiUrl('/api/v1/auth/login'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Authentication failed. Please verify credentials.');
      }

      login(data.access_token, data.user);
      navigate(fromPath, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Unable to connect to authentication server.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-split-wrapper">
      {/* Left Side: Cyber-Forensics Hero */}
      <AuthHero />

      {/* Right Side: Glassmorphism Login Card */}
      <div className="auth-form-section">
        <div className="auth-glass-card">
          {/* Brand Header */}
          <div style={{ textAlign: 'center', marginBottom: '26px' }}>
            <div style={{ marginBottom: '14px', display: 'flex', justifyContent: 'center' }}>
              <Logo size={70} alt="SecureMailScope X" />
            </div>

            <h2
              style={{
                fontSize: '18px',
                fontWeight: 700,
                letterSpacing: '-0.01em',
                color: '#ffffff',
                fontFamily: 'Inter, sans-serif',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '4px',
              }}
            >
              SecureMailScope{' '}
              <span
                style={{
                  color: 'var(--text-cyan, #06b6d4)',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
              >
                X
              </span>
            </h2>

            <p
              style={{
                fontSize: '12px',
                color: '#94a3b8',
                marginTop: '5px',
                lineHeight: 1.4,
              }}
            >
              Sign in to continue your investigation workspace.
            </p>
          </div>

          {/* Success Banner */}
          {successMessage && !error && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: 'rgba(16, 185, 129, 0.12)',
                border: '1px solid rgba(16, 185, 129, 0.35)',
                color: '#34d399',
                padding: '10px 12px',
                borderRadius: '8px',
                fontSize: '11.5px',
                marginBottom: '18px',
              }}
            >
              <CheckCircle size={15} style={{ flexShrink: 0 }} />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: 'rgba(244, 63, 94, 0.12)',
                border: '1px solid rgba(244, 63, 94, 0.35)',
                color: '#fb7185',
                padding: '10px 12px',
                borderRadius: '8px',
                fontSize: '11.5px',
                marginBottom: '18px',
              }}
            >
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div className="auth-input-group">
              <label className="auth-input-label">Email Address</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Mail size={14} />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@agency.gov"
                  className="auth-input-field"
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="auth-input-group">
              <label className="auth-input-label">Password</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Lock size={14} />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your access key / password"
                  className="auth-input-field"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="auth-input-toggle"
                  title={showPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="auth-submit-btn"
            >
              {isLoading ? (
                <span>AUTHENTICATING...</span>
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </form>

          {/* Footer Navigation Link */}
          <div
            style={{
              marginTop: '22px',
              paddingTop: '16px',
              borderTop: '1px solid rgba(6, 182, 212, 0.15)',
              textAlign: 'center',
              fontSize: '11.5px',
              color: '#94a3b8',
            }}
          >
            New to SecureMailScope X?{' '}
            <Link
              to="/register"
              style={{
                color: '#38bdf8',
                fontWeight: 600,
                textDecoration: 'none',
                marginLeft: '3px',
              }}
            >
              Register Analyst Profile
            </Link>
          </div>

          <div
            style={{
              marginTop: '14px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              fontSize: '10px',
              fontFamily: 'JetBrains Mono, monospace',
              color: '#64748b',
            }}
          >
            <ShieldCheck size={11} color="#06b6d4" />
            <span>Per-User Isolated Forensic Workspace</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
