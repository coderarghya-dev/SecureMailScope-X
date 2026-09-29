import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { AnalysisSummary } from '../types/forensic';
import {
  fetchAnalyses,
  fetchAnalysisDetail,
  uploadPCAP,
} from '../api/client';

interface AnalysisState {
  analyses: AnalysisSummary[];
  currentAnalysis: AnalysisSummary | null;
  isLoading: boolean;
  isAnalyzing: boolean;
  error: string | null;
  loadAnalyses: () => Promise<void>;
  selectAnalysis: (id: string) => Promise<void>;
  analyzeFile: (file: File) => Promise<AnalysisSummary>;
  clearCurrent: () => void;
  clearAll: () => void;
  clearError: () => void;
}

const normalizeConfidence = (
  analysis: AnalysisSummary | null
): AnalysisSummary | null => {
  if (!analysis) return null;

  const streamConfidence =
    analysis.streams?.[0]?.evidence_confidence?.score;

  const sessionConfidence =
    analysis.sessions?.[0]?.evidence_confidence?.score;

  const authoritativeConfidence =
    streamConfidence ??
    sessionConfidence ??
    analysis.evidence_confidence_score ??
    analysis.evidence_confidence;

  const confidenceLevel =
    analysis.streams?.[0]?.evidence_confidence?.level ??
    analysis.sessions?.[0]?.evidence_confidence?.level ??
    analysis.evidence_confidence_level;

  return {
    ...analysis,

    evidence_confidence:
      authoritativeConfidence !== undefined
        ? authoritativeConfidence
        : analysis.evidence_confidence,

    evidence_confidence_score:
      authoritativeConfidence !== undefined
        ? authoritativeConfidence
        : analysis.evidence_confidence_score,

    evidence_confidence_level:
      confidenceLevel ?? analysis.evidence_confidence_level,
  };
};

export const useAnalysisStore = create<AnalysisState>()(
  persist(
    (set) => ({
      analyses: [],
      currentAnalysis: null,
      isLoading: false,
      isAnalyzing: false,
      error: null,

      loadAnalyses: async () => {
        set({ isLoading: true, error: null });

        try {
          const data = await fetchAnalyses();

          const normalized = (data || []).map(
            (item) => normalizeConfidence(item)!
          );

          if (normalized.length === 0) {
            set({
              analyses: [],
              currentAnalysis: null,
              isLoading: false,
              error: null,
            });
            return;
          }

          const state = useAnalysisStore.getState();
          const existingCurrent = state.currentAnalysis;

          // Check if existingCurrent is still valid in user's analyses list and already has full details (streams populated)
          const isCurrentValid =
            existingCurrent &&
            Array.isArray(existingCurrent.streams) &&
            existingCurrent.streams.length > 0 &&
            normalized.some((a) => a.analysis_id === existingCurrent.analysis_id);

          if (isCurrentValid) {
            set({
              analyses: normalized,
              isLoading: false,
              error: null,
            });
          } else {
            // Need to fetch full detail for the target analysis
            const targetId =
              existingCurrent && normalized.some((a) => a.analysis_id === existingCurrent.analysis_id)
                ? existingCurrent.analysis_id
                : normalized[0].analysis_id;

            try {
              const fullDetail = await fetchAnalysisDetail(targetId);
              set({
                analyses: normalized,
                currentAnalysis: normalizeConfidence(fullDetail),
                isLoading: false,
                error: null,
              });
            } catch {
              // Fallback to summary item only if detail fetch fails
              set({
                analyses: normalized,
                currentAnalysis: normalized[0],
                isLoading: false,
                error: null,
              });
            }
          }
        } catch {
          set({
            analyses: [],
            currentAnalysis: null,
            isLoading: false,
          });
        }
      },

      selectAnalysis: async (id: string) => {
        set({ isLoading: true, error: null });

        try {
          const data = await fetchAnalysisDetail(id);

          set({
            currentAnalysis: normalizeConfidence(data),
            isLoading: false,
            error: null,
          });
        } catch (err: any) {
          set({
            error: err.message,
            isLoading: false,
          });
        }
      },

      analyzeFile: async (file: File) => {
        set({
          isAnalyzing: true,
          error: null,
        });

        try {
          const result = normalizeConfidence(
            await uploadPCAP(file)
          )!;

          set((state) => ({
            analyses: [
              result,
              ...state.analyses.filter(
                (a) => a.analysis_id !== result.analysis_id
              ),
            ],

            currentAnalysis: result,
            isAnalyzing: false,
            error: null,
          }));

          return result;
        } catch (err: any) {
          set({
            error: err.message,
            isAnalyzing: false,
          });

          throw err;
        }
      },

      clearCurrent: () =>
        set({
          currentAnalysis: null,
        }),

      clearAll: () => {
        localStorage.removeItem('securemailscope_analysis_cache');
        set({
          analyses: [],
          currentAnalysis: null,
          error: null,
        });
      },

      clearError: () =>
        set({
          error: null,
        }),
    }),

    {
      name: 'securemailscope_analysis_cache',

      partialize: (state) => ({
        analyses: state.analyses,
        currentAnalysis: state.currentAnalysis,
      }),

      onRehydrateStorage: () => (state) => {
        if (!state) return;

        state.currentAnalysis = normalizeConfidence(
          state.currentAnalysis
        );

        state.analyses = state.analyses.map(
          (analysis) => normalizeConfidence(analysis)!
        );
      },
    }
  )
);