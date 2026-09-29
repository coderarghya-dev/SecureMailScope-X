import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Lock, Mail, User, ArrowRight, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { getApiUrl } from '../api/client';
import { Logo } from '../components/common/Logo';
import { AuthHero } from '../components/auth/AuthHero';

export const RegisterPage: React.FC = () => {
  const navigate = useNavigate();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    setIsLoading(true);

    try {
      const res = await fetch(getApiUrl('/api/v1/auth/register'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: name.trim(),
          email: email.trim(),
          password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Registration failed. Please check inputs.');
      }

      // Do NOT auto-authenticate or persist token; redirect to login page
      navigate('/login', {
        replace: true,
        state: {
          successMessage: 'Account created successfully. Please sign in.',
          registeredEmail: email.trim(),
        },
      });
    } catch (err: any) {
      setError(err.message || 'Unable to connect to authentication server.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-split-wrapper">
      {/* Left 65%: Cinematic Cyber-Forensics Hero Stage */}
      <AuthHero />

      {/* Right 35%: Glassmorphism Registration Panel */}
      <div className="auth-form-section">
        <div className="auth-glass-card register-card">
          {/* Brand Header */}
          <div className="auth-card-header">
            <div className="auth-card-logo-wrap">
              <Logo size={95} alt="SecureMailScope X" />
            </div>

            <h2 className="auth-card-title">
              Analyst Onboarding
            </h2>

            <p className="auth-card-subtitle">
              Register secure profile for cryptographic investigations.
            </p>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="auth-alert-banner error">
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {/* Registration Form */}
          <form onSubmit={handleSubmit} className="auth-card-form register-form">
            <div className="auth-input-group">
              <label className="auth-input-label">Full Name / Call Sign</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <User size={15} />
                </div>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Agent John Doe"
                  className="auth-input-field"
                  autoComplete="name"
                />
              </div>
            </div>

            <div className="auth-input-group">
              <label className="auth-input-label">Analyst Email</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Mail size={15} />
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
              <label className="auth-input-label">Password (min 6 characters)</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Lock size={15} />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="auth-input-field"
                  autoComplete="new-password"
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

            <div className="auth-input-group">
              <label className="auth-input-label">Confirm Password</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Lock size={15} />
                </div>
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="auth-input-field"
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="auth-input-toggle"
                  title={showConfirmPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="auth-submit-btn"
            >
              {isLoading ? (
                <span>CREATING ACCOUNT...</span>
              ) : (
                <>
                  <span>Create Analyst Account</span>
                  <ArrowRight size={15} />
                </>
              )}
            </button>
          </form>

          {/* Footer Navigation Link */}
          <div className="auth-card-footer">
            Already have credentials?{' '}
            <Link to="/login" className="auth-footer-link">
              Sign In Here
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;
