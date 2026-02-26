export type OmniRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface OmniRiskInput {
  mode: 'web' | 'graphql' | 'direct_db' | 'ws' | 'mqtt' | 'grpc';
  maxParallel: number;
  vectorsCount: number;
  sqlRisk: number;
  sqlLevel: number;
}

export const computeOmniRiskLevel = (input: OmniRiskInput): OmniRiskLevel => {
  let score = input.maxParallel + input.vectorsCount;
  if (input.mode === 'web') score += 1;
  if (input.mode === 'graphql') score += 2;
  if (input.mode === 'direct_db') score += 3;
  if (input.mode === 'ws' || input.mode === 'mqtt' || input.mode === 'grpc') score += 2;
  if (input.sqlRisk >= 3) score += 2;
  if (input.sqlLevel >= 4) score += 1;
  if (score >= 13) return 'CRITICAL';
  if (score >= 10) return 'HIGH';
  if (score >= 7) return 'MEDIUM';
  return 'LOW';
};

