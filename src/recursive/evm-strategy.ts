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

const EVM_PASSES: RecursivePass[] = [
  {
    name: 'call-chain-tracing',
    description: 'Map external/public functions, inheritance, interfaces, and cross-contract call types',
    systemDirection: 'Enumerate all external and public functions. Map contract inheritance hierarchies and interface implementations. Identify every call, delegatecall, and staticcall to determine whether an attacker can reach sensitive internal logic through a public entry point.',
    expectedOutput: 'Array of cross-contract call chains with call type (call/delegatecall/staticcall), depth, and function visibility.',
  },
  {
    name: 'data-flow-expansion',
    description: 'Trace msg.sender, msg.value, custom struct args, and calldata to state writes or asset transfers',
    systemDirection: 'Track every user-supplied input — msg.sender (origin), msg.value (ETH attached), custom struct fields from calldata, and raw bytes payload — down to the precise storage slot write, balance update, or external transfer they influence. Highlight unchecked casts from calldata to storage.',
    expectedOutput: 'Expanded data flow mapping each input source to its final state write or asset transfer with slot/offset annotations.',
  },
  {
    name: 'self-verification',
    description: 'Re-analyze Solidity logic independently, check CEI and access controls',
    systemDirection: 'Re-analyze the contract logic independently of the original finding. Verify the Checks-Effects-Interactions pattern is respected. Confirm that require/assert guards on access control, reentrancy locks, and input validation are correctly placed and not bypassable via fallback or receive functions.',
    expectedOutput: 'Verification result indicating whether the original finding holds, is contradicted, or needs additional context.',
  },
  {
    name: 'vulnerability-chaining',
    description: 'Chain reentrancy, access control, oracle manipulation, and arithmetic flaws',
    systemDirection: 'Simulate multi-step attack sequences combining the following EVM vulnerability families: (1) Reentrancy — state changes after external calls, violation of CEI pattern, cross-function reentrancy; (2) Access Control & Initialization — missing initializer modifiers on upgradeable proxies, unprotected onlyOwner, flawed role derivation; (3) Economic Logic & Price Oracles — flash-loan-funded price manipulation, reliance on spot prices from low-liquidity AMM pools, sandwich/slippage manipulation vectors; (4) Arithmetic Precision — division-before-multiplication truncation leading to fee evasion, rounding errors that accumulate dust over repeated iterations.',
    expectedOutput: 'Array of vulnerability chains mapping step-by-step how one bug enables the next, with combined exploitability score.',
  },
  {
    name: 'poc-refinement',
    description: 'Iteratively improve Foundry/Hardhat-based exploit POCs',
    systemDirection: 'Iterate on the proof-of-concept exploit code, ensuring it is compatible with Foundry (forge test syntax) or Hardhat (ethers.js/waffle). Verify the transaction sequence correctly sets up state, executes the exploit, and asserts the outcome. Add proper fork network configuration, token approvals, and flash loan boilerplate where required.',
    expectedOutput: 'Refined POC in Foundry/Hardhat-compatible format with working assertions and state-change verification.',
  },
  {
    name: 'contradiction-detection',
    description: 'Detect CEI pattern violations and state transition inconsistencies',
    systemDirection: 'Analyze all recursive findings for logical contradictions specific to EVM smart contracts: (1) CEI pattern violation — external call placed before state mutation despite claims of safety; (2) Access control gap — finding claims a function is protected but calldata analysis shows a path around the guard via delegatecall or low-level call; (3) Oracle assumption mismatch — claimed TWAP oracle is actually a spot price feed; (4) Arithmetic inconsistency — rounding direction between finding and code differs.',
    expectedOutput: 'Array of contradictions found; empty if claims are internally consistent.',
  },
  {
    name: 'assumption-validation',
    description: 'Validate contract invariants, oracle assumptions, and upgrade assumptions',
    systemDirection: 'Challenge each assumption the vulnerability analysis makes: (1) Is the contract really upgradeable? Check for UUPS/transparent proxy patterns or a lack thereof; (2) Does the oracle actually return the price the model assumes? Verify the feed address and data flow; (3) Are flash loan preconditions actually met? Check token liquidity in referenced pools; (4) Can the attacker really control the calldata at every step? Check for msg.sender == tx.origin constraints.',
    expectedOutput: 'Array of validated assumptions with confidence level (high/medium/low) per assumption.',
  },
  {
    name: 'exploitability-proof',
    description: 'GOD-LEVEL: Prove DeFi exploitability via 5 Whys + 5 Hows',
    systemDirection: 'Execute a rigorous 5 Whys (root cause) and 5 Hows (attack path) prove-out: Why #1: Why can the user control this input? → Why #2: Why does this input reach the sensitive operation? → Why #3: Why is there no guard? → Why #4: Why does the guard fail? → Why #5: Why did the developer think it was safe?; How #1: How does the attacker reach the contract? → How #2: How does the attacker pass the check? → How #3: How does the exploit manipulate state? → How #4: How does the profit extraction work? → How #5: How is the attack undetectable?',
    expectedOutput: 'Array of proof steps with ✓ (validated) or MISSING/WARNING prefix for each Whys and Hows step.',
  },
];

export class EvmStrategy implements IRecursiveStrategy {
  readonly name = 'evm';
  readonly ecosystem = 'evm' as const;
  readonly passes = EVM_PASSES;

  getDataFlowPrompt(input: DataFlowPromptInput): string {
    const { vulnerability, depth, maxDepth } = input;
    return `[EVM] Trace user-controlled data flow in ${vulnerability.location.function} at ${vulnerability.location.file}:${vulnerability.location.line}.
Type: ${vulnerability.type}.

Follow each of these input sources independently:
1. msg.sender — can the caller's address influence logic (ownership checks, allowlists)?
2. msg.value — is ETH value used in accounting or state transitions?
3. Calldata parameters — trace struct fields, array lengths, and raw bytes to storage writes
4. Return data from external calls — is a return value trusted without validation?

For each source, identify:
- Which storage slots are written (contract:slot notation)?
- Which ERC-20/ETH transfers are triggered?
- Is there an unchecked calldata-to-struct cast (abi.decode without length check)?

Remaining recursion depth: ${maxDepth - depth}`;
  }

  getVerificationPrompt(input: VerificationPromptInput): string {
    return `[EVM] Independently verify this Solidity vulnerability finding.

Re-analyze the contract logic from first principles:

1. FUNCTION VISIBILITY — Is the vulnerable function actually external/public? Can a derived contract or fallback expose it differently?
2. CEI PATTERN — Does an external call (transfer, call, send) appear BEFORE state changes? Is there a reentrancy guard (ReentrancyGuard, mutex flag)?
3. ACCESS CONTROL — Is the modifier/check truly effective? Can msg.sender spoof it via delegatecall? Is the role derivation (e.g., keccak256(abi.encodePacked(...))) collision-prone?
4. INITIALIZATION — If proxy, is there an initializer modifier? Can initialize() be called again (upgradeable gap)?
5. ORACLE RELIANCE — Is the price feed manipulable? Minimum TWAP window? Is it a spot price from a low-liquidity pool?
6. ARITHMETIC — Are divisions performed before multiplications, causing precision truncation? Is rounding direction favorable to the user or the protocol?

Be critical — challenge the original finding. If the original analysis missed any of the above, flag it.`;
  }

  getChainPrompt(input: ChainPromptInput): string {
    const { vulnerability, depth, maxDepth } = input;
    return `[EVM] Identify vulnerability chains combining this finding with other contract weaknesses.

STARTING VULNERABILITY: ${vulnerability.type} at ${vulnerability.location.file}:${vulnerability.location.line}

Search for chains across these EVM-specific categories:

(1) REENTRANCY CHAINS
- Cross-function reentrancy: function A calls external → function B reads stale state
- Cross-contract reentrancy: Contract X calls Y, Y calls back into X before X's state writes
- Flash loan + reentrancy: borrow capital → trigger reentrancy → repay before state settles

(2) ACCESS CONTROL CHAINS
- Uninitialized proxy → delegatecall to attacker-deployed implementation
- Missing initializer → front-run initialize() to set own admin
- Role collision → register overlapping role hashes to escalate privileges

(3) ECONOMIC / ORACLE CHAINS
- Flash loan → manipulate pool price → trigger liquidation with inflated debt → steal collateral
- Sandwich: monitor mempool → front-run swap → back-run with manipulated price → extract MEV
- Donate to manipulate time-weighted average price (TWAP) if window is short

(4) ARITHMETIC CHAINS
- Division truncation → fee underpayment → accumulate dust → drain over N iterations
- Rounding mismatch between deposit() and withdraw() → mint/redeem imbalance

(5) DELEGATECALL CHAINS
- Storage collision between logic and proxy → overwrite critical implementation address
- delegatecall to user-controlled address → arbitrary execution

Maximum chain depth: ${maxDepth - depth}

Format each chain as: [precondition] → [trigger] → [exploit step] → [profit]`;
  }

  getPOCRefinementPrompt(input: POCPromptInput): string {
    const { poc, vulnerability, iteration } = input;
    return `[EVM] Refine this Foundry/Hardhat proof-of-concept exploit.

Vulnerability: ${vulnerability.type} (${vulnerability.severity || 'unknown'})
Contract: ${vulnerability.location.file}

Review and improve the current POC:

1. EXECUTION CONTEXT — Add the correct Solidity version pragma / Hardhat network config. If Foundry, use vm.createSelectFork(<rpc>, <block>) to reproduce state.
2. SETUP — Ensure all prerequisite token approvals, WETH deposits, and flash loan initialization steps are present.
3. EXPLOIT SEQUENCE — Verify the transaction ordering: borrow → manipulate → drain → repay. Each step should emit actionable events or show storage changes.
4. ASSERTIONS — Add assertEq / expectRevert calls proving the exploit worked (e.g., attacker balance increased, contract balance drained).
5. GAS CONSIDERATIONS — If the exploit runs out of gas, add gas limits or split across multiple transactions.
6. EDGE CASES — Does the exploit depend on a specific block number? A specific pool liquidity level? Add setUp() with the exact on-chain state fork.

Current POC:
${JSON.stringify(poc, null, 2)}

Return the refined version. If this is iteration ${iteration + 1} of 3, focus on fixing any issues flagged in the previous round.`;
  }

  async proveExploitability(
    vulnerability: Vulnerability,
    context: CodeContext,
    recursiveData: RecursiveAnalysis | null
  ): Promise<string[]> {
    const proof: string[] = [];

    // WHY #1: Why can the attacker control this input?
    const hasUserInput = vulnerability.attackerControlled?.entryPoint
      || context.files.some(f =>
          f.functions.some(fn =>
            fn.name === (vulnerability.location.function || '') &&
            (fn.userInputs.length > 0 || fn.sensitiveSinks.length > 0)
          )
        );
    if (hasUserInput) {
      proof.push(`✓ Why #1: External/public function ${vulnerability.location.function} accepts attacker-controlled calldata`);
    } else {
      proof.push('WARNING Why #1: No clear external entry point identified for attacker input');
    }

    // WHY #2: Why does this input reach the sensitive operation?
    const dataFlow = vulnerability.attackerControlled?.dataFlow;
    if (dataFlow && dataFlow.length > 0) {
      proof.push(`✓ Why #2: Data flow traces ${dataFlow.length} hops from input to sensitive operation`);
    } else {
      proof.push('WARNING Why #2: Data flow not fully traced — blind spot between input and sink');
    }

    // WHY #3: Why is there no guard?
    const hasGuard = context.files.some(f =>
      f.functions.some(fn =>
        fn.name === (vulnerability.location.function || '') &&
        fn.sensitiveSinks.some(s => /require|revert|assert/i.test(s))
      )
    );
    if (!hasGuard) {
      proof.push('✓ Why #3: No access control or reentrancy guard on the function');
    } else {
      proof.push('WARNING Why #3: Guard exists — verify it is correctly implemented and not bypassable');
    }

    // WHY #4: Why does the guard fail?
    if (!hasGuard) {
      proof.push('✓ Why #4: (No guard to fail — direct access)');
    } else {
      proof.push('✓ Why #4: Guard logic evaluated — checking for bypass paths (delegatecall, fallback)');
    }

    // WHY #5: Why did the developer think it was safe?
    proof.push('✓ Why #5: Root cause identified — developer assumed CEI pattern held or input validation was sufficient');

    // HOW #1: How does the attacker reach the contract?
    proof.push(`✓ How #1: Attacker crafts calldata targeting ${vulnerability.location.file}:${vulnerability.location.function} via direct transaction or proxy`);

    // HOW #2: How does the attacker pass the check?
    const needsBypass = hasGuard;
    if (needsBypass) {
      proof.push('WARNING How #2: Guard bypass required — searching for delegatecall/fallback paths around the check');
    } else {
      proof.push('✓ How #2: No check to bypass — function is unprotected');
    }

    // HOW #3: How does the exploit manipulate state?
    const hasStateWrite = recursiveData?.findings.some(f => f.type === 'data-flow-expansion') || false;
    if (hasStateWrite) {
      proof.push('✓ How #3: Data-flow expansion confirms state manipulation path');
    } else {
      proof.push('WARNING How #3: State manipulation path inferred but not recursively validated');
    }

    // HOW #4: How does profit extraction work?
    const profitType = vulnerability.type?.toLowerCase() || '';
    if (/drain|steal|transfer|withdraw/.test(profitType)) {
      proof.push('✓ How #4: Asset extraction via direct transfer/withdraw call');
    } else if (/price|oracle|manipulation/.test(profitType)) {
      proof.push('✓ How #4: Profit via price discrepancy after oracle manipulation');
    } else {
      proof.push('✓ How #4: Profit mechanism identified through vulnerability type analysis');
    }

    // HOW #5: How is the attack undetectable?
    proof.push('✓ How #5: Attack surfaces as normal transaction sequence — detection requires on-chain monitoring of CEI violations or storage slot writes');

    return proof;
  }

  detectContradictions(
    vulnerability: Vulnerability,
    recursive: RecursiveAnalysis
  ): string[] {
    const contradictions: string[] = [];

    // CEI pattern contradiction: finding claims no CEI violation but analysis found one
    for (const chain of recursive.callChains) {
      if (chain.vulnerableAt && chain.vulnerableAt !== vulnerability.location.function) {
        contradictions.push(
          `CEI CONTRADICTION: Call chain analysis shows vulnerability in ${chain.vulnerableAt}, ` +
          `but original analysis claims ${vulnerability.location.function}. ` +
          `The actual external call may occur before state changes in ${chain.vulnerableAt}.`
        );
      }
    }

    // Verification contradiction
    const verification = recursive.findings.find(f => f.type === 'deeper-analysis');
    if (verification?.details?.verified === false) {
      const reason = verification.details.reason || 'unknown';
      if (/reentrancy|guard|CEI/i.test(reason)) {
        contradictions.push(`CEI CONTRADICTION: Self-verification failed — ${reason}`);
      } else if (/access|auth|admin|only/i.test(reason)) {
        contradictions.push(`ACCESS CONTRADICTION: Self-verification failed — ${reason}`);
      } else {
        contradictions.push(`SELF-VERIFICATION CONTRADICTION: ${reason}`);
      }
    } else if (verification?.details?.verified === undefined || verification?.details?.verified === null) {
      contradictions.push('VERIFICATION UNCERTAIN: Insufficient information to confirm or deny the finding');
    }

    // Data flow expansion: check for storage slot disagreements
    const dataFlowFindings = recursive.findings.filter(f => f.type === 'data-flow-expansion');
    for (const expansion of dataFlowFindings) {
      if (expansion.details?.contradicts) {
        contradictions.push(`DATA-FLOW CONTRADICTION: ${expansion.details.contradicts}`);
      }
      // Check if expanded data flow shows a different storage slot being written
      if (expansion.details?.storageSlots && vulnerability.location?.line) {
        // Flag if the expansion found additional affected slots not mentioned in the original finding
        contradictions.push(`STORAGE CONTRADICTION: Data-flow expansion reveals additional storage slots affected beyond original analysis`);
      }
    }

    // Oracle assumption contradiction
    const oracleMention = recursive.findings.some(f =>
      f.details && JSON.stringify(f.details).toLowerCase().includes('twap')
    );
    const spotMention = recursive.findings.some(f =>
      f.details && JSON.stringify(f.details).toLowerCase().includes('spot')
    );
    if (oracleMention && spotMention) {
      contradictions.push('ORACLE CONTRADICTION: Analysis claims TWAP but references spot price data');
    }

    return contradictions;
  }
}
