import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  UploadCloud,
  Layers,
  AlertTriangle,
  Lock,
  Cpu,
  FileCode2,
  Link as ChainIcon,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Terminal,
  Activity,
  FileCheck
} from 'lucide-react';
import { useHealthStore } from '../../store/useHealthStore';
import { StatusIndicator } from '../common/StatusIndicator';
import { Logo } from '../common/Logo';

interface NavItem {
  name: string;
  path: string;
  icon: React.ReactNode;
  planned?: boolean;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: 'INVESTIGATE',
    items: [
      { name: 'Dashboard', path: '/dashboard', icon: <LayoutDashboard size={14} /> },
      { name: 'Ingestion Station', path: '/analyze', icon: <UploadCloud size={14} /> },
      { name: 'Session Matrix', path: '/sessions', icon: <Layers size={14} /> },
      { name: 'Security Findings', path: '/findings', icon: <AlertTriangle size={14} /> },
      { name: 'Posture Monitoring', path: '/monitoring', icon: <Activity size={14} /> },
      { name: 'Remediation Playbooks', path: '/remediation', icon: <FileCheck size={14} /> },
    ]
  },
  {
    title: 'CRYPTOGRAPHY',
    items: [
      { name: 'Crypto Posture', path: '/crypto', icon: <Lock size={14} /> },
      { name: 'PQC Readiness', path: '/pqc', icon: <Cpu size={14} /> },
    ]
  },
  {
    title: 'EVIDENCE',
    items: [
      { name: 'Packet Explorer', path: '/packets', icon: <FileCode2 size={14} /> },
      { name: 'Chain of Custody', path: '/custody', icon: <ChainIcon size={14} /> },
      { name: 'Reports & Export', path: '/reports', icon: <FileText size={14} /> },
    ]
  },
  {
    title: 'SYSTEM',
    items: [
      { name: 'Diagnostics & Settings', path: '/settings', icon: <Settings size={14} /> }
    ]
  }
];

export const Sidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const { isOnline, health } = useHealthStore();

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Brand Header */}
      <div
        className="sidebar-header"
        style={{
          justifyContent: collapsed ? 'center' : 'flex-start',
          padding: collapsed ? '0 10px' : '0 16px',
        }}
      >
        <Logo size="sm" showWordmark={!collapsed} alt="SecureMailScope X" />
      </div>

      {/* Navigation Groups */}
      <nav className="sidebar-nav">
        {NAV_GROUPS.map((group) => (
          <div key={group.title} style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
            {!collapsed ? (
              <div className="sidebar-group-title">
                {group.title}
              </div>
            ) : (
              <div style={{ borderTop: '1px solid var(--border-subtle)', margin: '4px 0', opacity: 0.5 }} />
            )}

            {group.items.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `sidebar-link ${isActive ? 'active' : ''}`
                }
                style={{
                  justifyContent: collapsed ? 'center' : 'flex-start',
                  padding: collapsed ? '7px 0' : '6px 10px',
                }}
                title={collapsed ? item.name : undefined}
              >
                <span style={{ width: '15px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  {item.icon}
                </span>

                {!collapsed && (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flex: 1, minWidth: 0 }}>
                    <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.name}</span>
                    {item.planned && (
                      <span
                        style={{
                          fontSize: '8px',
                          fontFamily: 'JetBrains Mono, monospace',
                          padding: '1px 3px',
                          borderRadius: '2px',
                          textTransform: 'uppercase',
                          color: 'var(--text-purple)',
                          backgroundColor: 'var(--accent-pqc-bg)',
                          border: '1px solid var(--accent-pqc-border)',
                        }}
                      >
                        Plan
                      </span>
                    )}
                  </div>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Operational Status Footer */}
      <div className="sidebar-footer">
        {!collapsed ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', overflow: 'hidden' }}>
            <StatusIndicator status={isOnline ? 'online' : 'offline'} label={isOnline ? 'API Active' : 'Offline'} />
            {health?.tshark_available && (
              <span
                style={{
                  fontSize: '9px',
                  fontFamily: 'JetBrains Mono, monospace',
                  color: 'var(--text-cyan)',
                  backgroundColor: 'var(--accent-cyan-bg)',
                  border: '1px solid var(--accent-cyan-border)',
                  padding: '1px 4px',
                  borderRadius: '2px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '3px',
                }}
              >
                <Terminal size={9} />
                <span>TShark</span>
              </span>
            )}
          </div>
        ) : (
          <div style={{ margin: '0 auto' }}>
            <StatusIndicator status={isOnline ? 'online' : 'offline'} showText={false} />
          </div>
        )}

        <button
          onClick={() => setCollapsed(!collapsed)}
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: '4px',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {collapsed ? <ChevronRight size={13} /> : <ChevronLeft size={13} />}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
