import React from 'react';
import logoImg from '../../assets/logo.png';

export interface LogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl' | number;
  className?: string;
  style?: React.CSSProperties;
  imgStyle?: React.CSSProperties;
  showWordmark?: boolean;
  alt?: string;
}

const SIZE_MAP: Record<string, number> = {
  sm: 26,
  md: 44,
  lg: 72,
  xl: 96,
};

export const Logo: React.FC<LogoProps> = ({
  size = 'md',
  className = '',
  style,
  imgStyle,
  showWordmark = false,
  alt = 'SecureMailScope X',
}) => {
  const pixelSize = typeof size === 'number' ? size : SIZE_MAP[size] || 44;

  return (
    <div
      className={`brand-logo-lockup ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: showWordmark ? (pixelSize > 40 ? '12px' : '9px') : '0',
        lineHeight: 1,
        ...style,
      }}
    >
      <img
        src={logoImg}
        alt={alt}
        style={{
          width: `${pixelSize}px`,
          height: `${pixelSize}px`,
          objectFit: 'contain',
          flexShrink: 0,
          filter: 'drop-shadow(0 2px 8px rgba(6, 182, 212, 0.25))',
          ...imgStyle,
        }}
      />
      {showWordmark && (
        <div style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          <span
            className="sidebar-brand-title"
            style={{
              fontSize: pixelSize >= 44 ? '16px' : '13.5px',
              fontWeight: 700,
              color: '#ffffff',
              letterSpacing: '-0.01em',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              lineHeight: 1.15,
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
          </span>
          <span
            className="sidebar-brand-subtitle"
            style={{
              fontSize: pixelSize >= 44 ? '9.5px' : '8.5px',
              fontFamily: 'JetBrains Mono, monospace',
              color: 'var(--text-muted, #94a3b8)',
              letterSpacing: '0.05em',
              textTransform: 'uppercase',
              marginTop: '1px',
            }}
          >
            Cryptographic Forensics
          </span>
        </div>
      )}
    </div>
  );
};
