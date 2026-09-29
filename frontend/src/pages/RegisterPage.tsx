import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Lock, Mail, User, ArrowRight, AlertCircle, Eye, EyeOff, ShieldCheck } from 'lucide-react';
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
      {/* Left Side: Cyber-Forensics Hero */}
      <AuthHero />

      {/* Right Side: Glassmorphism Register Card */}
      <div className="auth-form-section">
        <div className="auth-glass-card">
          {/* Brand Header */}
          <div style={{ textAlign: 'center', marginBottom: '24px' }}>
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
              Analyst Onboarding
            </h2>

            <p
              style={{
                fontSize: '12px',
                color: '#94a3b8',
                marginTop: '5px',
                lineHeight: 1.4,
              }}
            >
              Register secure profile for cryptographic investigations.
            </p>
          </div>

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
                marginBottom: '16px',
              }}
            >
              <AlertCircle size={15} style={{ flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {/* Registration Form */}
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="auth-input-group">
              <label className="auth-input-label">Full Name / Call Sign</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <User size={14} />
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
              <label className="auth-input-label">Password (min 6 characters)</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Lock size={14} />
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
                  {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <div className="auth-input-group">
              <label className="auth-input-label">Confirm Password</label>
              <div className="auth-input-container">
                <div className="auth-input-icon">
                  <Lock size={14} />
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
                  {showConfirmPassword ? <EyeOff size={15} /> : <Eye size={15} />}
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
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </form>

          {/* Footer Navigation Link */}
          <div
            style={{
              marginTop: '20px',
              paddingTop: '16px',
              borderTop: '1px solid rgba(6, 182, 212, 0.15)',
              textAlign: 'center',
              fontSize: '11.5px',
              color: '#94a3b8',
            }}
          >
            Already have credentials?{' '}
            <Link
              to="/login"
              style={{
                color: '#38bdf8',
                fontWeight: 600,
                textDecoration: 'none',
                marginLeft: '3px',
              }}
            >
              Sign In Here
            </Link>
          </div>

          <div
            style={{
              marginTop: '12px',
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
            <span>Encrypted Credential Storage &amp; Workspace Isolation</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;
