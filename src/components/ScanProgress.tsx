import { SCAN_PHASES } from '@/lib/scanner-data';
import { Shield, Radio, Globe, Lock, Bug, FileText, Network, ArrowRightLeft, Plug, Code, Unlink, ExternalLink, ScanSearch } from 'lucide-react';

interface ScanProgressProps {
  currentPhaseIndex: number;
  phaseProgress: number;
}

const phaseIcons = [Radio, Network, Globe, ArrowRightLeft, FileText, Lock, Bug, ScanSearch, Plug, Code, Unlink, ExternalLink, Shield];

const ScanProgress = ({ currentPhaseIndex, phaseProgress }: ScanProgressProps) => {
  return (
    <div className="space-y-3">
      {SCAN_PHASES.map((phase, index) => {
        const Icon = phaseIcons[index];
        const isComplete = index < currentPhaseIndex;
        const isCurrent = index === currentPhaseIndex;
        const isPending = index > currentPhaseIndex;

        return (
          <div key={phase.id} className="flex items-center gap-3">
            <div
              className={`w-8 h-8 rounded-md flex items-center justify-center border transition-all duration-300 ${
                isComplete
                  ? 'bg-success/20 border-success text-success'
                  : isCurrent
                  ? 'bg-primary/20 border-primary text-primary animate-pulse-glow'
                  : 'bg-secondary border-border text-muted-foreground'
              }`}
            >
              <Icon className="w-4 h-4" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between">
                <span
                  className={`text-sm font-medium ${
                    isComplete
                      ? 'text-success'
                      : isCurrent
                      ? 'text-primary'
                      : 'text-muted-foreground'
                  }`}
                >
                  {phase.name}
                </span>
                <span className="text-xs text-muted-foreground">
                  {isComplete ? '100%' : isCurrent ? `${Math.round(phaseProgress)}%` : '—'}
                </span>
              </div>
              <div className="mt-1 h-1 rounded-full bg-secondary overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${
                    isComplete ? 'bg-success' : isCurrent ? 'bg-primary' : ''
                  }`}
                  style={{ width: isComplete ? '100%' : isCurrent ? `${phaseProgress}%` : '0%' }}
                />
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default ScanProgress;
