import React from 'react';

export const AuthHero: React.FC = () => {
  return (
    <div className="auth-hero-section" role="region" aria-label="SecureMailScope X Cyber Forensics Platform">
      {/* Visual content is fully rendered in the pristine high-resolution canvas matching Image B */}
      <div
        style={{
          position: 'absolute',
          width: '1px',
          height: '1px',
          padding: 0,
          margin: '-1px',
          overflow: 'hidden',
          clip: 'rect(0, 0, 0, 0)',
          whiteSpace: 'nowrap',
          borderWidth: 0,
        }}
      >
        <h1>SecureMailScope X</h1>
        <p>Passive email cryptographic forensics and evidence-bound analysis.</p>
        <ul>
          <li>INVESTIGATE: Trace, analyze and verify email origins with confidence.</li>
          <li>PRESERVE: Maintain cryptographic evidence and full audit trails.</li>
          <li>UNCOVER TRUTH: Turn email data into actionable intelligence.</li>
        </ul>
      </div>
    </div>
  );
};

