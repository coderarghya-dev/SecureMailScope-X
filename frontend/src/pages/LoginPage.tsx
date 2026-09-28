import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Shield, Lock, Mail, ArrowRight, AlertCircle } from 'lucide-react';
import { useAuthStore } from '../store/useAuthStore';
import { getApiUrl } from '../api/client';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuthStore();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

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
        throw new Error(data.detail || 'Authentication failed. Please verify credentials.');
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
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'var(--bg-app, #0a0e17)',
        padding: '20px',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Background Grid Pattern */}
      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage:
            'linear-gradient(rgba(148, 163, 184, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(148, 163, 184, 0.03) 1px, transparent 1px)',
          backgroundSize: '32px 32px',
          pointerEvents: 'none',
        }}
      />

      <div
        style={{
          width: '100%',
          maxWidth: '420px',
          backgroundColor: 'var(--surface-elevated, #131b2e)',
          border: '1px solid var(--border-medium, rgba(6, 182, 212, 0.25))',
          borderRadius: 'var(--radius-lg, 8px)',
          padding: '32px',
          boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5), 0 0 16px rgba(6, 182, 212, 0.1)',
          position: 'relative',
          zIndex: 1,
        }}
      >
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '44px',
              height: '44px',
              borderRadius: '10px',
              backgroundColor: 'rgba(6, 182, 212, 0.12)',
              border: '1px solid rgba(6, 182, 212, 0.3)',
              marginBottom: '12px',
            }}
          >
            <Shield size={22} color="var(--accent-cyan, #06b6d4)" />
          </div>

          <div
            style={{
              fontSize: '17px',
              fontWeight: 700,
              letterSpacing: '0.05em',
              color: '#f8fafc',
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            SECUREMAILSCOPE X
          </div>

          <div
            style={{
              fontSize: '11.5px',
              color: 'var(--text-muted, #94a3b8)',
              marginTop: '4px',
            }}
          >
            Cryptographic Forensics &amp; Chain of Custody
          </div>
        </div>

        {error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              backgroundColor: 'rgba(244, 63, 94, 0.12)',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              color: 'var(--text-rose, #f43f5e)',
              padding: '10px 12px',
              borderRadius: 'var(--radius-sm, 4px)',
              fontSize: '11px',
              marginBottom: '18px',
            }}
          >
            <AlertCircle size={14} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div>
            <label
              style={{
                display: 'block',
                fontSize: '10.5px',
                fontFamily: 'JetBrains Mono, monospace',
                color: 'var(--text-secondary, #cbd5e1)',
                textTransform: 'uppercase',
                marginBottom: '6px',
                fontWeight: 600,
              }}
            >
              Analyst Email
            </label>
            <div style={{ position: 'relative' }}>
              <div
                style={{
                  position: 'absolute',
                  left: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted, #64748b)',
                  display: 'flex',
                  alignItems: 'center',
                }}
              >
                <Mail size={14} />
              </div>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@agency.gov"
                style={{
                  width: '100%',
                  padding: '9px 12px 9px 32px',
                  backgroundColor: 'var(--surface-primary, #0c1222)',
                  border: '1px solid var(--border-subtle, #1e293b)',
                  borderRadius: 'var(--radius-sm, 4px)',
                  color: '#f8fafc',
                  fontSize: '12px',
                  fontFamily: 'JetBrains Mono, monospace',
                  outline: 'none',
                  transition: 'border-color 0.15s ease',
                }}
              />
            </div>
          </div>

          <div>
            <label
              style={{
                display: 'block',
                fontSize: '10.5px',
                fontFamily: 'JetBrains Mono, monospace',
                color: 'var(--text-secondary, #cbd5e1)',
                textTransform: 'uppercase',
                marginBottom: '6px',
                fontWeight: 600,
              }}
            >
              Access Key / Password
            </label>
            <div style={{ position: 'relative' }}>
              <div
                style={{
                  position: 'absolute',
                  left: '10px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--text-muted, #64748b)',
                  display: 'flex',
                  alignItems: 'center',
                }}
              >
                <Lock size={14} />
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                style={{
                  width: '100%',
                  padding: '9px 12px 9px 32px',
                  backgroundColor: 'var(--surface-primary, #0c1222)',
                  border: '1px solid var(--border-subtle, #1e293b)',
                  borderRadius: 'var(--radius-sm, 4px)',
                  color: '#f8fafc',
                  fontSize: '12px',
                  fontFamily: 'JetBrains Mono, monospace',
                  outline: 'none',
                  transition: 'border-color 0.15s ease',
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="btn-primary"
            style={{
              marginTop: '8px',
              padding: '10px',
              justifyContent: 'center',
              fontSize: '12px',
              fontWeight: 600,
              letterSpacing: '0.04em',
              cursor: isLoading ? 'not-allowed' : 'pointer',
              opacity: isLoading ? 0.7 : 1,
            }}
          >
            {isLoading ? (
              <span>AUTHENTICATING...</span>
            ) : (
              <>
                <span>ENTER WORKSTATION</span>
                <ArrowRight size={13} />
              </>
            )}
          </button>
        </form>

        <div
          style={{
            marginTop: '24px',
            paddingTop: '18px',
            borderTop: '1px solid var(--border-subtle, #1e293b)',
            textAlign: 'center',
            fontSize: '11px',
            color: 'var(--text-muted, #94a3b8)',
          }}
        >
          Need analyst access?{' '}
          <Link
            to="/register"
            style={{
              color: 'var(--accent-cyan, #06b6d4)',
              fontWeight: 600,
              textDecoration: 'none',
            }}
          >
            Register Credentials
          </Link>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
