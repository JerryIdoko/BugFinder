import { RecursiveAnalyzer, RecursiveAnalysis } from './recursive-analyzer.js';
import { Vulnerability } from '../detector/vulnerability-detector.js';
import { CodeContext } from '../analyzer/context-analyzer.js';
import { ProviderConfig } from '../agents/model-executor.js';
import { IRecursiveStrategy, Ecosystem } from './strategy-types.js';
import { TraditionalStrategy } from './traditional-strategy.js';
import { EvmStrategy } from './evm-strategy.js';
import { SorobanStrategy } from './soroban-strategy.js';

const strategyMap: Record<Ecosystem, new () => IRecursiveStrategy> = {
  traditional: TraditionalStrategy,
  evm: EvmStrategy,
  soroban: SorobanStrategy,
};

export interface RecursiveConfig {
  enabled: boolean;
  maxDepth: number;
  strategies: RecursiveStrategy[];
  refinementIterations: number;
  providerConfig?: ProviderConfig;
  ecosystem?: Ecosystem;
}

export type RecursiveStrategy =
  | 'call-chain-tracing'
  | 'data-flow-expansion'
  | 'self-verification'
  | 'vulnerability-chaining'
  | 'poc-refinement'
  | 'contradiction-detection'
  | 'assumption-validation'
  | 'exploitability-proof';

export class RecursiveStrategyEngine {
  private analyzer: RecursiveAnalyzer;
  private config: RecursiveConfig;
  private strategy: IRecursiveStrategy;

  constructor(config: RecursiveConfig) {
    this.config = config;

    const StrategyClass = strategyMap[config.ecosystem || 'traditional'];
    this.strategy = new StrategyClass();

    this.analyzer = new RecursiveAnalyzer(config.maxDepth, config.providerConfig, this.strategy);
  }

  getActiveStrategy(): IRecursiveStrategy {
    return this.strategy;
  }

  async apply(
    vulnerabilities: Vulnerability[],
    context: CodeContext
  ): Promise<EnhancedVulnerability[]> {
    if (!this.config.enabled) {
      return vulnerabilities.map(v => ({ ...v, recursive: null }));
    }

    console.log(`  Recursive strategy: ${this.strategy.name} (${this.strategy.passes.length} passes)`);

    const enhanced: EnhancedVulnerability[] = [];

    for (const vuln of vulnerabilities) {
      console.log(`  Recursive analysis: ${vuln.id}`);

      let recursiveData: RecursiveAnalysis | null = null;

      if (this.shouldApplyStrategy('call-chain-tracing') ||
          this.shouldApplyStrategy('data-flow-expansion') ||
          this.shouldApplyStrategy('self-verification') ||
          this.shouldApplyStrategy('vulnerability-chaining')) {

        recursiveData = await this.analyzer.recursiveDeepen(vuln, context, 0);
      }

      let refinedPOC = vuln.poc;
      if (this.shouldApplyStrategy('poc-refinement') && vuln.poc) {
        refinedPOC = await this.analyzer.recursiveRefine(
          vuln.poc,
          vuln,
          this.config.refinementIterations
        );
      }

      let exploitabilityProof: string[] = [];
      if (this.shouldApplyStrategy('exploitability-proof')) {
        exploitabilityProof = await this.strategy.proveExploitability(vuln, context, recursiveData);
      }

      let contradictions: string[] = [];
      let verificationStatus: 'verified' | 'uncertain' | 'contradicted' = 'verified';

      if (this.shouldApplyStrategy('contradiction-detection') && recursiveData) {
        contradictions = this.strategy.detectContradictions(vuln, recursiveData);

        if (contradictions.length > 0) {
          const hasUncertainty = contradictions.some(c =>
            c.includes('uncertain') ||
            c.includes('verification inconclusive') ||
            c.includes('insufficient information')
          );

          if (hasUncertainty) {
            verificationStatus = 'uncertain';
            console.log(`    Verification uncertain for ${vuln.id} with Sonnet`);

            if (vuln.severity === 'critical' || vuln.severity === 'high') {
              console.log(`    → Retrying verification with Opus (higher model)...`);
              const opusRecursiveData = await this.analyzer.recursiveDeepen(vuln, context, 0, 'opus');
              const opusContradictions = this.strategy.detectContradictions(vuln, opusRecursiveData);

              const opusHasUncertainty = opusContradictions.some(c =>
                c.includes('uncertain') ||
                c.includes('verification inconclusive') ||
                c.includes('insufficient information')
              );

              if (opusContradictions.length === 0) {
                verificationStatus = 'verified';
                recursiveData = opusRecursiveData;
                contradictions = [];
                console.log(`    ✓ Opus verified ${vuln.id} - upgraded to VERIFIED`);
              } else if (!opusHasUncertainty) {
                verificationStatus = 'contradicted';
                recursiveData = opusRecursiveData;
                contradictions = opusContradictions;
                console.log(`    ✗ Opus contradicted ${vuln.id} - downgraded to CONTRADICTED`);
              } else {
                recursiveData = opusRecursiveData;
                contradictions = opusContradictions;
                console.log(`    ⚠ Opus also uncertain for ${vuln.id} - keeping as UNCERTAIN`);
              }
            } else {
              console.log(`    → Skipping Opus retry (only for critical/high severity)`);
            }
          } else {
            verificationStatus = 'contradicted';
            console.log(`    Found contradictions in ${vuln.id}, marking as low confidence`);
          }
        }
      }

      const passedExploitabilityChecks = exploitabilityProof.filter(p => p.startsWith('✓')).length;
      const totalExploitabilityChecks = 5;

      enhanced.push({
        ...vuln,
        poc: refinedPOC,
        recursive: recursiveData,
        verificationStatus,
        contradictions: contradictions.length > 0 ? contradictions : undefined,
        confidence: verificationStatus === 'verified' ? 'high' :
                   verificationStatus === 'uncertain' ? 'medium' : 'low',
        needsManualReview: verificationStatus !== 'verified',
        recursiveExploitabilityProof: exploitabilityProof.length > 0 ? {
          validationsPassed: passedExploitabilityChecks,
          validationsTotal: totalExploitabilityChecks,
          proofSteps: exploitabilityProof,
          isFullyProven: passedExploitabilityChecks === totalExploitabilityChecks
        } : undefined
      });
    }

    return enhanced;
  }

  private shouldApplyStrategy(strategy: RecursiveStrategy): boolean {
    return this.config.strategies.includes(strategy);
  }
}

export interface EnhancedVulnerability extends Vulnerability {
  recursive: RecursiveAnalysis | null;
  recursiveExploitabilityProof?: {
    validationsPassed: number;
    validationsTotal: number;
    proofSteps: string[];
    isFullyProven: boolean;
  };
}
