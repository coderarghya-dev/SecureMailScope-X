import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Lock, Mail, ArrowRight, AlertCircle, CheckCircle, Eye, EyeOff, Shield, HelpCircle } from 'lucide-react';
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
  const [rememberMe, setRememberMe] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
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
    setNotice(null);
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

  const handleForgotPassword = (e: React.MouseEvent) => {
    e.preventDefault();
    setNotice('Password recovery is managed by your organization security administrator.');
  };

  const handleSSOLogin = (e: React.MouseEvent) => {
    e.preventDefault();
    setNotice('Enterprise SSO provider redirection initiated. Contact SOC administrator if unconfigured.');
  };

  return (
    <div className="auth-split-wrapper">
      {/* Top Right "Need Help?" Link (Image B exact match: outside card, top-right) */}
      <a
        href="#help"
        onClick={(e) => {
          e.preventDefault();
          setNotice('Forensic analyst documentation & SOC helpdesk is available on internal channel.');
        }}
        className="auth-top-help"
      >
        <HelpCircle size={15} />
        <span>Need Help?</span>
      </a>

      {/* Left 67%: Cinematic Cyber-Forensics Hero Stage */}
      <AuthHero />

      {/* Right 33%: Glassmorphism Authentication Panel */}
      <div className="auth-form-section">
        <div className="auth-glass-card">
          {/* Brand Header */}
          <div className="auth-card-header">
            <div className="auth-card-logo-wrap">
              <Logo size={105} alt="SecureMailScope X" />
            </div>

            <h2 className="auth-card-title">
              SecureMailScope<span className="auth-brand-x">X</span>
            </h2>

            <p className="auth-card-subtitle">
              Sign in to continue your<br />investigation workspace.
            </p>
          </div>

          {/* Success Banner */}
          {successMessage && !error && !notice && (
            <div className="auth-alert-banner success">
              <CheckCircle size={15} style={{ flexShrink: 0 }} />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Notice Banner */}
          {notice && !error && (
            <div className="auth-alert-banner success" style={{ backgroundColor: 'rgba(0, 210, 255, 0.12)', borderColor: 'rgba(0, 210, 255, 0.35)', color: '#38bdf8' }}>
              <CheckCircle size={15} style={{ flexShrink: 0 }} />
              <span>{notice}</span>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div className="auth-alert-banner error">
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {/* Login Form */}
          <form onSubmit={handleSubmit} className="auth-card-form">
            <div className="auth-input-group">
              <label className="auth-input-label">Email Address</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Mail size={15} />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="auth-input-field"
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="auth-input-group">
              <label className="auth-input-label">Password</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Lock size={15} />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
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
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* Remember Me & Forgot Password Row (Image B Match) */}
            <div className="auth-remember-row">
              <label className="auth-remember-label">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="auth-remember-checkbox"
                />
                <span>Remember me</span>
              </label>
              <a href="#forgot" onClick={handleForgotPassword} className="auth-forgot-link">
                Forgot password?
              </a>
            </div>

            {/* Submit Button */}
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
                  <ArrowRight size={15} />
                </>
              )}
            </button>

            {/* OR Divider (Image B Match) */}
            <div className="auth-divider">
              <span>OR</span>
            </div>

            {/* SSO Button (Image B Match) */}
            <button
              type="button"
              onClick={handleSSOLogin}
              className="auth-sso-btn"
            >
              <Shield size={16} color="#00d2ff" />
              <span>Sign in with SSO</span>
            </button>
          </form>

          {/* Footer Navigation Link (Image B Exact Match) */}
          <div className="auth-card-footer">
            New to SecureMailScope X?{' '}
            <Link to="/register" className="auth-footer-link">
              Contact your administrator.
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
