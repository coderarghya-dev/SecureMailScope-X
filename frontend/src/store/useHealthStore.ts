import { create } from 'zustand';
import { SystemHealth } from '../types/forensic';
import { fetchHealth } from '../api/client';

interface HealthState {
  health: SystemHealth | null;
  isOnline: boolean;
  isLoading: boolean;
  error: string | null;
  checkHealth: () => Promise<void>;
}

export const useHealthStore = create<HealthState>((set) => ({
  health: null,
  isOnline: false,
  isLoading: false,
  error: null,
  checkHealth: async () => {
    set({ isLoading: true });
    try {
      const data = await fetchHealth();
      set({ health: data, isOnline: true, error: null, isLoading: false });
    } catch (err: any) {
      set({ isOnline: false, error: err.message, isLoading: false });
    }
  },
}));
