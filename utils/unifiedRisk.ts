import { computeOmniRiskLevel, type OmniRiskInput, type OmniRiskLevel } from './omniRisk';

export type UnifiedRiskLevel = OmniRiskLevel;

export interface UnifiedRiskInput extends OmniRiskInput {}

export const computeUnifiedRiskLevel = (input: UnifiedRiskInput): UnifiedRiskLevel =>
  computeOmniRiskLevel(input);
