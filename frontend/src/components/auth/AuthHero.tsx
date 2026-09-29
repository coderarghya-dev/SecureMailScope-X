import React from 'react';
import { Shield, FileText, Activity, Lock } from 'lucide-react';
import { Logo } from '../common/Logo';

export const AuthHero: React.FC = () => {
  return (
    <div className="auth-hero-section">
      {/* Top Brand Bar */}
      <div>
        <div className="auth-hero-top">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Logo size={22} alt="SecureMailScope X" />
            <span
              style={{
                fontSize: '13px',
                fontWeight: 700,
                color: '#f8fafc',
                letterSpacing: '-0.01em',
              }}
            >
              SecureMailScope{' '}
              <span
                style={{
                  color: '#06b6d4',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
              >
                X
              </span>
            </span>
          </div>

          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '3px 9px',
              borderRadius: '12px',
              backgroundColor: 'rgba(6, 182, 212, 0.08)',
              border: '1px solid rgba(6, 182, 212, 0.22)',
              fontSize: '9.5px',
              fontFamily: 'JetBrains Mono, monospace',
              color: '#38bdf8',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
            }}
          >
            <Lock size={10} color="#06b6d4" />
            <span>Forensics Engine</span>
          </div>
        </div>

        {/* Hero Title & Subtitle */}
        <div style={{ marginTop: '28px' }}>
          <h1 className="auth-hero-title">
            WELCOME TO <br />
            <span style={{ color: '#38bdf8' }}>SECUREMAILSCOPE X</span>
          </h1>
          <p className="auth-hero-subtitle">
            Passive Email Cryptographic Forensics &amp; Evidence-Bound Analysis
          </p>
        </div>
      </div>

      {/* Center Cyber-Forensics Focal Emblem (No screenshots or mockups) */}
      <div className="auth-hero-focal">
        <div className="auth-focal-glow" />
        <div className="auth-focal-circle">
          <Logo size={105} alt="SecureMailScope X Cyber Forensics" />
        </div>
        <div className="auth-focal-badge">
          <Lock size={11} color="#06b6d4" />
          <span>FIPS 140-3 &amp; RFC Compliance Standard</span>
        </div>
      </div>

      {/* 3 Simple Capability Rows */}
      <div>
        <div className="auth-capability-rows">
          {/* 1. INVESTIGATE */}
          <div className="auth-capability-row">
            <div className="auth-row-icon">
              <Shield size={14} />
            </div>
            <div>
              <div className="auth-row-title">INVESTIGATE</div>
              <div className="auth-row-desc">
                Trace and analyze cryptographic email evidence.
              </div>
            </div>
          </div>

          {/* 2. PRESERVE */}
          <div className="auth-capability-row">
            <div className="auth-row-icon">
              <FileText size={14} />
            </div>
            <div>
              <div className="auth-row-title">PRESERVE</div>
              <div className="auth-row-desc">
                Maintain verifiable evidence and audit trails.
              </div>
            </div>
          </div>

          {/* 3. VERIFY */}
          <div className="auth-capability-row">
            <div className="auth-row-icon">
              <Activity size={14} />
            </div>
            <div>
              <div className="auth-row-title">VERIFY</div>
              <div className="auth-row-desc">
                Generate evidence-bound forensic assessments.
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
