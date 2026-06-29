import { Vulnerability } from '../detector/vulnerability-detector.js';
import { CodeContext } from '../analyzer/context-analyzer.js';
import { RecursiveAnalysis } from './recursive-analyzer.js';

export type Ecosystem = 'evm' | 'soroban' | 'traditional';

export interface RecursivePass {
  name: string;
  description: string;
  systemDirection: string;
  expectedOutput: string;
}

export interface DataFlowPromptInput {
  vulnerability: Vulnerability;
  depth: number;
  maxDepth: number;
}

export interface VerificationPromptInput {
  vulnerability: Vulnerability;
  depth: number;
}

export interface ChainPromptInput {
  vulnerability: Vulnerability;
  depth: number;
  maxDepth: number;
}

export interface POCPromptInput {
  poc: any;
  vulnerability: Vulnerability;
  iteration: number;
}

export interface IRecursiveStrategy {
  readonly name: string;
  readonly ecosystem: Ecosystem;

  /** Metadata for all 8 recursive passes */
  readonly passes: RecursivePass[];

  /** Prompt template for data-flow expansion */
  getDataFlowPrompt(input: DataFlowPromptInput): string;

  /** Prompt template for self-verification */
  getVerificationPrompt(input: VerificationPromptInput): string;

  /** Prompt template for vulnerability chaining */
  getChainPrompt(input: ChainPromptInput): string;

  /** Prompt template for POC refinement */
  getPOCRefinementPrompt(input: POCPromptInput): string;

  /**
   * Runs ecosystem-specific exploitability proof validation.
   * Returns an array of proof strings (prefixed with ✓ or WARNING/MISSING).
   */
  proveExploitability(
    vulnerability: Vulnerability,
    context: CodeContext,
    recursiveData: RecursiveAnalysis | null
  ): Promise<string[]>;

  /**
   * Detects contradictions in the recursive analysis results.
   * Returns an array of contradiction descriptions (empty = no contradictions).
   */
  detectContradictions(
    vulnerability: Vulnerability,
    recursive: RecursiveAnalysis
  ): string[];
}
