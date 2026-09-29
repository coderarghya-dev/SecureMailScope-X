import React from 'react';
import { Shield, FileText, Activity, Lock, Cpu, Sparkles } from 'lucide-react';
import { Logo } from '../common/Logo';
import heroForensicsImg from '../../assets/hero-forensics.jpg';

export const AuthHero: React.FC = () => {
  return (
    <div className="auth-hero-section">
      {/* Top Brand Bar */}
      <div>
        <div className="auth-hero-top">
          <Logo size="sm" showWordmark alt="SecureMailScope X" />
          <div className="auth-hero-badge">
            <Sparkles size={11} color="#38bdf8" />
            <span>Forensic Evidence Engine</span>
          </div>
        </div>

        {/* Hero Title & Subtitle */}
        <div style={{ marginTop: '12px' }}>
          <h1 className="auth-hero-title">
            WELCOME TO <br />
            <span
              style={{
                background: 'linear-gradient(135deg, #ffffff 0%, #38bdf8 50%, #06b6d4 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              SECUREMAILSCOPE X
            </span>
          </h1>
          <p className="auth-hero-subtitle">
            Passive email cryptographic forensics and evidence-bound analysis.
          </p>
        </div>
      </div>

      {/* Center Hero Artwork / Digital Forensics Showcase */}
      <div className="auth-illustration-container">
        <img
          src={heroForensicsImg}
          alt="SecureMailScope X Cyber Forensics Illustration"
          className="auth-illustration-img"
        />
        {/* Holographic Cyan Glass Tint Overlay */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            background: 'linear-gradient(180deg, rgba(6, 182, 212, 0.05) 0%, rgba(10, 18, 36, 0.4) 100%)',
            pointerEvents: 'none',
          }}
        />
        <div
          style={{
            position: 'absolute',
            bottom: '12px',
            left: '14px',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            padding: '4px 10px',
            borderRadius: '6px',
            backgroundColor: 'rgba(6, 11, 20, 0.75)',
            border: '1px solid rgba(6, 182, 212, 0.3)',
            backdropFilter: 'blur(8px)',
            fontSize: '10.5px',
            fontFamily: 'JetBrains Mono, monospace',
            color: '#38bdf8',
          }}
        >
          <Lock size={11} color="#06b6d4" />
          <span>FIPS 140-3 &amp; RFC-Bounded Analysis</span>
        </div>
      </div>

      {/* 3 Capability Statements */}
      <div>
        <div className="auth-capabilities-grid">
          {/* 1. INVESTIGATE */}
          <div className="auth-capability-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div className="auth-capability-icon">
                <Shield size={16} />
              </div>
              <span className="auth-capability-title">INVESTIGATE</span>
            </div>
            <p className="auth-capability-desc">
              Trace and analyze cryptographic email evidence.
            </p>
          </div>

          {/* 2. PRESERVE */}
          <div className="auth-capability-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div className="auth-capability-icon">
                <FileText size={16} />
              </div>
              <span className="auth-capability-title">PRESERVE</span>
            </div>
            <p className="auth-capability-desc">
              Maintain verifiable evidence and audit trails.
            </p>
          </div>

          {/* 3. VERIFY */}
          <div className="auth-capability-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div className="auth-capability-icon">
                <Activity size={16} />
              </div>
              <span className="auth-capability-title">VERIFY</span>
            </div>
            <p className="auth-capability-desc">
              Generate evidence-bound forensic assessments.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
