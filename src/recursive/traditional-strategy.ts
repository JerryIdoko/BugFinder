import { Vulnerability } from '../detector/vulnerability-detector.js';
import { CodeContext } from '../analyzer/context-analyzer.js';
import { RecursiveAnalysis } from './recursive-analyzer.js';
import {
  IRecursiveStrategy,
  RecursivePass,
  DataFlowPromptInput,
  VerificationPromptInput,
  ChainPromptInput,
  POCPromptInput,
} from './strategy-types.js';

const PASSES: RecursivePass[] = [
  {
    name: 'call-chain-tracing',
    description: 'Trace function calls recursively',
    systemDirection: 'Trace function calls from sink back to entry points, identifying all callers recursively.',
    expectedOutput: 'Array of call chains with depth, taint status, and vulnerable function locations.',
  },
  {
    name: 'data-flow-expansion',
    description: 'Expand data flows recursively',
    systemDirection: 'Trace data flows from sources to sinks recursively, identifying all transformation steps.',
    expectedOutput: 'Expanded data flow with new sources, sinks, and transformation paths.',
  },
  {
    name: 'self-verification',
    description: 'Model verifies own findings',
    systemDirection: 'Independently re-analyze the code to verify the finding. Be critical and challenge assumptions.',
    expectedOutput: 'Verification result with confirmed or contradicted status and reasoning.',
  },
  {
    name: 'vulnerability-chaining',
    description: 'Find chains of bugs',
    systemDirection: 'Look for additional vulnerabilities that could chain with this one to create higher impact.',
    expectedOutput: 'Array of vulnerability chains with combined exploitability scores.',
  },
  {
    name: 'poc-refinement',
    description: 'Iteratively improve POCs',
    systemDirection: 'Improve the proof-of-concept by making it more reliable, adding error handling, and fixing issues.',
    expectedOutput: 'Refined POC with improved reliability and coverage.',
  },
  {
    name: 'contradiction-detection',
    description: 'Recursively check for logical contradictions',
    systemDirection: 'Analyze recursive findings for logical inconsistencies that might indicate hallucination.',
    expectedOutput: 'Array of contradictions found, empty if none detected.',
  },
  {
    name: 'assumption-validation',
    description: 'Recursively validate assumptions',
    systemDirection: 'Challenge and validate each assumption made during the analysis.',
    expectedOutput: 'Validated assumptions with confidence levels.',
  },
  {
    name: 'exploitability-proof',
    description: 'GOD-LEVEL: Recursively prove user-controlled exploitation',
    systemDirection: 'Use 5 Whys (root cause) + 5 Hows (attack path) methodology to prove exploitability.',
    expectedOutput: 'Array of proof steps prefixed with ✓ or WARNING/MISSING status.',
  },
];

export class TraditionalStrategy implements IRecursiveStrategy {
  readonly name = 'traditional';
  readonly ecosystem = 'traditional' as const;
  readonly passes = PASSES;

  getDataFlowPrompt(input: DataFlowPromptInput): string {
    const { vulnerability, depth, maxDepth } = input;
    const file = vulnerability.location.file;
    const func = vulnerability.location.function;
    const line = vulnerability.location.line;
    const type = vulnerability.type;
    return `Recursively trace data flow in ${func} at ${file}:${line}.
Type: ${type}. Find sources and sinks. Then trace those recursively.
Remaining depth: ${maxDepth - depth}`;
  }

  getVerificationPrompt(input: VerificationPromptInput): string {
    const { vulnerability, depth } = input;
    return `Verify this vulnerability by:
1. Re-analyzing the code independently
2. Checking if the data flow is correct
3. Confirming the exploit path exists
4. Looking for mitigations you might have missed

If you find any errors in the original analysis, explain what was wrong.
If you find additional context, include it.

Be critical - challenge the original finding.`;
  }

  getChainPrompt(input: ChainPromptInput): string {
    const { vulnerability, depth, maxDepth } = input;
    return `Look for OTHER vulnerabilities that could chain with this one.

Examples:
- XSS + CSRF = account takeover
- SSRF + weak auth = cloud metadata theft
- Path traversal + code execution = RCE
- Info leak + SQL injection = data breach

Find vulnerabilities that:
1. Are reachable from this vulnerability
2. Combine to create higher impact
3. Form a complete attack chain

Maximum chain depth: ${maxDepth - depth}`;
  }

  getPOCRefinementPrompt(input: POCPromptInput): string {
    const { poc, vulnerability, iteration } = input;
    return `Improve this POC by:
1. Making it more reliable
2. Adding error handling
3. Making it easier to run
4. Adding more detailed output
5. Fixing any issues from iteration ${iteration}

Previous POC:
${JSON.stringify(poc, null, 2)}

Return an improved version.`;
  }

  async proveExploitability(
    vulnerability: Vulnerability,
    context: CodeContext,
    recursiveData: RecursiveAnalysis | null
  ): Promise<string[]> {
    const proof: string[] = [];

    // RECURSIVE VALIDATION #1: 5 Whys - Trace back to user input
    if (!vulnerability.attackerControlled?.entryPoint) {
      proof.push('MISSING: Entry point not specified - cannot trace user input');
    } else {
      proof.push(`✓ Entry Point: ${vulnerability.attackerControlled.entryPoint}`);
    }

    if (!vulnerability.attackerControlled?.dataFlow || vulnerability.attackerControlled.dataFlow.length === 0) {
      proof.push('MISSING: Data flow not traced - cannot prove user control');
    } else {
      proof.push(`✓ Data Flow: ${vulnerability.attackerControlled.dataFlow.length} hops from input to sink`);
      if (recursiveData) {
        const dataFlowFindings = recursiveData.findings.filter(f => f.type === 'data-flow-expansion');
        if (dataFlowFindings.length > 0) {
          proof.push(`✓ Recursive verification: Data flow validated at ${dataFlowFindings.length} depth levels`);
        }
      }
    }

    // RECURSIVE VALIDATION #2: 5 Hows - Prove exploitation steps
    if (!vulnerability.attackerControlled?.attackPath) {
      proof.push('MISSING: Attack path not documented - cannot prove exploitability');
    } else {
      proof.push(`✓ Attack Path: ${vulnerability.attackerControlled.attackPath.substring(0, 100)}...`);
    }

    if (!vulnerability.attackVector || vulnerability.attackVector.length < 20) {
      proof.push('MISSING: Detailed attack vector - exploitation scenario incomplete');
    } else {
      proof.push(`✓ Attack Vector: Detailed scenario provided (${vulnerability.attackVector.length} chars)`);
    }

    // RECURSIVE VALIDATION #3: Check call chains support the attack path
    if (recursiveData && recursiveData.callChains.length > 0) {
      const vulnerableChains = recursiveData.callChains.filter(c => c.vulnerableAt);
      if (vulnerableChains.length > 0) {
        proof.push(`✓ Call Chain: ${vulnerableChains.length} vulnerable call paths identified`);
      } else {
        proof.push('WARNING: No vulnerable call chains found in recursive analysis');
      }
    }

    // RECURSIVE VALIDATION #4: Verify preconditions are achievable
    if (vulnerability.exploitationDependencies) {
      const impossible = vulnerability.exploitationDependencies.required.filter(
        (d: any) => d.feasibility === 'theoretical'
      );
      if (impossible.length > 0) {
        proof.push(`WARNING: ${impossible.length} theoretical dependencies - exploitation may be impractical`);
      } else {
        proof.push('✓ Dependencies: All prerequisites are achievable');
      }
    }

    // RECURSIVE VALIDATION #5: Check reachability
    if (vulnerability.reachability && !vulnerability.reachability.isReachable) {
      proof.push(`WARNING: Code not reachable - ${vulnerability.reachability.reason || 'unknown reason'}`);
    } else {
      proof.push('✓ Reachability: Code is reachable by attackers');
    }

    return proof;
  }

  detectContradictions(
    vulnerability: Vulnerability,
    recursive: RecursiveAnalysis
  ): string[] {
    const contradictions: string[] = [];

    for (const chain of recursive.callChains) {
      if (chain.vulnerableAt && chain.vulnerableAt !== vulnerability.location.function) {
        contradictions.push(
          `Call chain shows vulnerability in ${chain.vulnerableAt}, ` +
          `but original analysis says ${vulnerability.location.function}`
        );
      }
    }

    const verification = recursive.findings.find(f => f.type === 'deeper-analysis');
    if (verification?.details?.verified === false) {
      const reason = verification.details.reason || 'unknown';
      if (reason.includes('insufficient') || reason.includes('unclear') ||
          reason.includes('uncertain') || reason.includes('inconclusive')) {
        contradictions.push(`verification inconclusive: ${reason}`);
      } else {
        contradictions.push(`Self-verification failed: ${reason}`);
      }
    } else if (verification?.details?.verified === undefined || verification?.details?.verified === null) {
      contradictions.push('verification uncertain: insufficient information to confirm or deny');
    }

    const dataFlowExpansions = recursive.findings.filter(
      f => f.type === 'data-flow-expansion'
    );
    for (const expansion of dataFlowExpansions) {
      if (expansion.details?.contradicts) {
        contradictions.push(
          `Data flow analysis contradicts original: ${expansion.details.contradicts}`
        );
      }
    }

    return contradictions;
  }
}
