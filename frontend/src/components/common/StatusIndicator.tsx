import React from 'react';

interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'warning' | 'busy';
  label?: string;
  showText?: boolean;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  label,
  showText = true,
}) => {
  const getStatusColor = () => {
    switch (status) {
      case 'online':
        return { dot: 'bg-emerald-400', ring: 'ring-emerald-400/30', text: 'text-emerald-400' };
      case 'offline':
        return { dot: 'bg-rose-500', ring: 'ring-rose-500/30', text: 'text-rose-400' };
      case 'warning':
        return { dot: 'bg-amber-400', ring: 'ring-amber-400/30', text: 'text-amber-400' };
      case 'busy':
        return { dot: 'bg-cyan-400 animate-pulse', ring: 'ring-cyan-400/30', text: 'text-cyan-400' };
      default:
        return { dot: 'bg-slate-400', ring: 'ring-slate-400/30', text: 'text-slate-400' };
    }
  };

  const colors = getStatusColor();

  return (
    <div className="flex items-center gap-1.5 shrink-0" title={label}>
      <span className="relative flex h-2 w-2">
        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${colors.dot}`} />
        <span className={`relative inline-flex rounded-full h-2 w-2 ${colors.dot}`} />
      </span>
      {showText && label && (
        <span className={`text-[10.5px] font-mono font-medium ${colors.text}`}>
          {label}
        </span>
      )}
    </div>
  );
};

export default StatusIndicator;
