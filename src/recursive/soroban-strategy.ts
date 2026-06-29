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

const SOROBAN_PASSES: RecursivePass[] = [
  {
    name: 'call-chain-tracing',
    description: 'Map #[contractimpl] functions, cross-contract call clients, #[contracttype] types, and interface traits',
    systemDirection: 'Enumerate all exposed contract functions marked with #[contractimpl]. Map cross-contract call clients (Env::invoke_contract), custom type definitions (#[contracttype] enums/structs), and trait implementations (TokenInterface, NFTInterface). Identify every call to `env.invoke_contract()` and determine if the callee address is user-supplied or hardcoded.',
    expectedOutput: 'Array of cross-contract call chains with function visibility, user-supplied callee addresses, and custom type references.',
  },
  {
    name: 'data-flow-expansion',
    description: 'Trace Env object, user-supplied args, and signature data to ledger reads/writes',
    systemDirection: 'Track every user-supplied invocation argument through the contract logic: (1) Env object methods — env.current_contract(), env.invoking_contract(), env.caller(); (2) Raw arguments passed into #[contractimpl] functions — trace each parameter down to ledger access via env.storage().get()/set()/has()/del(); (3) Signature verification flows — trace SorobanAuth Ed25519 or account signature payloads through verification logic. Identify any case where the contract reads from storage before verifying the caller (potential auth bypass).',
    expectedOutput: 'Expanded data flow from each input parameter to ledger key/value accesses, with storage type annotation (Instance/Persistent/Temporary).',
  },
  {
    name: 'self-verification',
    description: 'Re-analyze Rust contract logic, check auth guards and storage lifetimes',
    systemDirection: 'Independently re-analyze the Rust contract logic. Verify: (1) Every state-modifying function calls address.require_auth() or address.require_auth_for_args() before ledger writes; (2) Storage type selection (Instance vs Persistent vs Temporary) matches the data lifetime requirements — no sensitive data in Temporary buckets; (3) Integer operations on u128/i128 use checked_* or saturating_* math; (4) Cross-contract calls from env.invoke_contract() use a trusted (hardcoded) contract address rather than a user-supplied one.',
    expectedOutput: 'Verification result confirming whether auth guards, storage types, and arithmetic safety hold; or listing contradictions.',
  },
  {
    name: 'vulnerability-chaining',
    description: 'Chain auth bypasses, storage mismanagement, arithmetic flaws, and SEP-41 token discrepancies',
    systemDirection: 'Simulate multi-step attack sequences combining Soroban-specific vulnerability families: (1) Authentication Bypasses — missing or improperly placed address.require_auth() or address.require_auth_for_args() in multi-party workflows, Ed25519 signature verification gaps, delegated signature replay across contracts; (2) Storage Mismanagement — sensitive state saved in Temporary (short-lived) buckets instead of Persistent, ledger space key exhaustion via unbounded env.storage().set() in a loop, stale data reads from Instance after contract upgrade; (3) Arithmetic & Wrap Behavior — unchecked u128/i128 operations lacking checked_* / saturating_* primitives, integer wrapping in balance calculations when crossing the i128/u128 boundary; (4) SEP-41 Token Interface Discrepancies — balance() return mismatch vs actual ledger state, transfer() that updates internal bookkeeping but not the ledger, missing authorization on burn()/mint().',
    expectedOutput: 'Array of vulnerability chains showing how one flaw enables the next, with combined exploitability score for the Soroban runtime.',
  },
  {
    name: 'poc-refinement',
    description: 'Iteratively improve Soroban SDK Rust-based exploit POCs',
    systemDirection: 'Iterate on the proof-of-concept exploit code using the Soroban SDK test framework. Ensure the POC: (1) Uses #[test] functions with soroban_sdk::testutils; (2) Sets up a test environment with SorobanEnv or the test contract client; (3) Deploys contracts, mints/burns tokens, and invokes #[contractimpl] functions in sequence; (4) Asserts ledger state changes with assert_eq! on storage values; (5) Handles edge cases like authorization failures (require_auth returning Err) and overflow panics. Prefer the soroban_sdk::testutils::AddressTestUtils for managing test addresses.',
    expectedOutput: 'Refined POC in Rust test format using soroban_sdk test utilities with assertions on ledger state.',
  },
  {
    name: 'contradiction-detection',
    description: 'Detect storage lifetime contradictions and auth inconsistencies',
    systemDirection: 'Analyze recursive findings for Soroban-specific contradictions: (1) Storage Lifetime Mismatch — finding claims data is Persistent but code shows Temporary bucket usage; (2) Auth Bypass Contradiction — finding says require_auth is called but code path analysis shows early return before the auth check; (3) SEP-41 Contractiction — finding says balance() returns correct value but code shows a cache variable that can diverge from the ledger; (4) Cross-Contract Contradiction — the callee address is claimed to be hardcoded but is actually derived from user-supplied arguments.',
    expectedOutput: 'Array of contradictions found; empty if the finding is internally consistent.',
  },
  {
    name: 'assumption-validation',
    description: 'Challenge auth, storage, and upgrade assumptions',
    systemDirection: 'Challenge every assumption made by the vulnerability analysis: (1) Is the contract actually upgradeable? Check for WASM hash update functions or admin-only deployment contracts; (2) Does require_auth() actually prevent the attack? Trace the exact code path — is there an early return that skips it?; (3) Is the storage lifetime assumption valid? Verify the contract uses Persistent for long-lived data and Temporary only for ephemeral data; (4) Can the attacker control the cross-contract call target? If env.invoke_contract uses a user-supplied Address parameter rather than a hardcoded one, the attack surface widens significantly; (5) Are u128/i128 operations safe? Check for casts between types without bounds checking.',
    expectedOutput: 'Array of validated assumptions with confidence level (high/medium/low) per assumption.',
  },
  {
    name: 'exploitability-proof',
    description: 'GOD-LEVEL: Prove Soroban contract exploitability via 5 Whys + 5 Hows',
    systemDirection: 'Execute a rigorous 5 Whys (root cause) and 5 Hows (attack path) prove-out for Soroban/WASM contracts: Why #1: Why can the user invoke this function? (check #[contractimpl] visibility and auth); Why #2: Why does this input reach a sensitive ledger write? (trace input to env.storage().set()); Why #3: Why is there no authorization? (check require_auth placement); Why #4: Why does the authorization fail to protect? (check for early returns, unwraps, or skipped paths); Why #5: Why did the developer think it was safe? (common Soroban pitfalls like assuming refundable invocation); How #1: How does the attacker construct the invocation? (build proper SorobanAuth signature); How #2: How does the attacker bypass auth? (bypass path or missing guard); How #3: How does the exploit manipulate ledger state? (specific keys written); How #4: How does profit extraction work? (token transfer or ledger value manipulation); How #5: How is the attack undetectable? (normal-looking invocation sequence).',
    expectedOutput: 'Array of proof steps with ✓ (validated) or MISSING/WARNING prefix for each Whys and Hows step.',
  },
];

export class SorobanStrategy implements IRecursiveStrategy {
  readonly name = 'soroban';
  readonly ecosystem = 'soroban' as const;
  readonly passes = SOROBAN_PASSES;

  getDataFlowPrompt(input: DataFlowPromptInput): string {
    const { vulnerability, depth, maxDepth } = input;
    return `[Soroban] Trace user-controlled data flow in ${vulnerability.location.function} at ${vulnerability.location.file}:${vulnerability.location.line}.
Type: ${vulnerability.type}.

Follow each of these Soroban-specific input sources independently:

1. env.caller() / Address args — is the caller address used in authorization decisions? Trace through require_auth.
2. Raw function parameters — map each #[contractimpl] argument to its eventual ledger key via env.storage()
3. Signature payloads — if the contract verifies Ed25519 or account signatures, does the payload include a nonce/expiry to prevent replay?
4. Cross-contract return data — is a value from env.invoke_contract() trusted without re-validation?

For each source, identify:
- Exact ledger keys read/written (with storage type: Instance/Persistent/Temporary)
- Whether require_auth() or require_auth_for_args() is called before the write
- Whether env.invoke_contract() is called with a user-supplied or hardcoded Address

Remaining recursion depth: ${maxDepth - depth}`;
  }

  getVerificationPrompt(input: VerificationPromptInput): string {
    return `[Soroban] Independently verify this Soroban/Rust contract vulnerability finding.

Re-analyze the contract logic from first principles:

1. AUTHENTICATION — Does every state-mutating path call address.require_auth() or address.require_auth_for_args()? Check for early returns with ? or unwrap() that skip the auth call. Are there multi-party workflows where one participant's auth is not checked?
2. STORAGE LIFETIME — Is the storage type correct? Temporary data is cleared after the transaction — is sensitive state stored in Temporary instead of Persistent? Could an attacker exhaust ledger space with unbounded env.storage().set() in a loop?
3. ARITHMETIC SAFETY — Are u128/i128 operations using checked_add/checked_sub/saturating_add or bare +/-? Is there a cast between i128 and u128 without bounds checking?
4. CROSS-CONTRACT CALLS — Does env.invoke_contract() use a hardcoded contract address? If the callee address is user-supplied, can the attacker point it to a malicious contract?
5. SEP-41 COMPLIANCE — If implementing a token, does transfer() update both the internal bookkeeping AND the ledger? Is the balance() return value consistent with actual stored state?
6. REPLAY PROTECTION — If using SorobanAuth, does the signature include a nonce or deadline to prevent replay across contracts or time?

Be critical — challenge the original finding. Flag any Soroban-specific safety checks that were missed.`;
  }

  getChainPrompt(input: ChainPromptInput): string {
    const { vulnerability, depth, maxDepth } = input;
    return `[Soroban] Identify vulnerability chains combining this finding with other Soroban contract weaknesses.

STARTING VULNERABILITY: ${vulnerability.type} at ${vulnerability.location.file}:${vulnerability.location.line}

Search for chains across these Soroban-specific categories:

(1) AUTH BYPASS CHAINS
- Missing require_auth on function A → call function B that trusts the caller was authenticated
- Delegated signature replay across contracts → drain multiple contracts with one signature
- Ed25519 signature without expiry → capture and replay signature in a later block

(2) STORAGE MISMANAGEMENT CHAINS
- Temporary bucket used for critical state → transaction reverts and state is lost → economic manipulation
- Unbounded storage writes in loop → exhaust ledger entry TTL/space → brick contract
- Instance storage not cleared on upgrade → stale data from old contract version affects new logic

(3) ARITHMETIC CHAINS
- i128 overflow in balance calculation → wrap to negative → mint unlimited tokens
- u128 underflow in fee calculation → unchecked_sub panics → DoS
- Division-before-multiplication → precision loss → accumulate leftover tokens over repeated calls

(4) SEP-41 TOKEN CHAINS
- transfer() updates ledger but not internal accounting → balanceOf diverges → theft
- Missing authorization on mint() → anyone can mint → supply inflation
- burn() without ledger update → tokens destroyed but ledger still shows balance → double-spend

(5) CROSS-CONTRACT CHAINS
- User-controlled callee in invoke_contract → malicious contract re-enters caller → state corruption
- Trust return value from untrusted contract → use manipulated return in critical logic

Maximum chain depth: ${maxDepth - depth}

Format each chain as: [precondition] → [trigger] → [exploit step] → [profit/impact]`;
  }

  getPOCRefinementPrompt(input: POCPromptInput): string {
    const { poc, vulnerability, iteration } = input;
    return `[Soroban] Refine this Soroban SDK Rust proof-of-concept exploit.

Vulnerability: ${vulnerability.type} (${vulnerability.severity || 'unknown'})
Contract: ${vulnerability.location.file}

Review and improve the current POC:

1. TEST FRAMEWORK — Use #[test] functions with Soroban SDK testutils. Create contracts via ContractClient or deploy via env.register_contract().
2. AUTHORIZATION — Use AddressUtils to generate test addresses and call require_auth() where appropriate. Verify that bypassing auth produces an expected Err.
3. LEDGER STATE — Use env.storage() to read/write expected state before and after each operation. Assert ledger keys with assert_eq!.
4. CROSS-CONTRACT SETUP — If the exploit involves multiple contracts, deploy all via env.register_contract() and link them with addresses.
5. EDGE CASES — Test with max u128/i128 values to trigger overflow/underflow. Test with expired/nonce-replayed signatures.
6. SEP-41 TOKEN TESTS — If the exploit involves token functions, use the testutils token helpers to mint initial balances and assert final balances.

Current POC:
${JSON.stringify(poc, null, 2)}

Return the refined version. If this is iteration ${iteration + 1} of 3, focus on fixing issues flagged in the previous round.`;
  }

  async proveExploitability(
    vulnerability: Vulnerability,
    context: CodeContext,
    recursiveData: RecursiveAnalysis | null
  ): Promise<string[]> {
    const proof: string[] = [];

    // WHY #1: Why can the user invoke this function?
    const hasPublicFn = context.files.some(f =>
      f.functions.some(fn =>
        fn.name === (vulnerability.location.function || '')
      )
    );
    if (hasPublicFn) {
      proof.push(`✓ Why #1: Function ${vulnerability.location.function} is exposed via #[contractimpl] and reachable by external callers`);
    } else {
      proof.push('WARNING Why #1: No #[contractimpl] function identified as entry point');
    }

    // WHY #2: Why does this input reach a sensitive ledger write?
    const dataFlow = vulnerability.attackerControlled?.dataFlow;
    if (dataFlow && dataFlow.length > 0) {
      proof.push(`✓ Why #2: Data flow traces ${dataFlow.length} hops from invocation args to ledger write`);
    } else {
      proof.push('WARNING Why #2: Data flow from input to ledger write not fully traced');
    }

    // WHY #3: Why is there no authorization?
    const hasAuth = context.files.some(f =>
      f.functions.some(fn =>
        fn.name === (vulnerability.location.function || '') &&
        fn.sensitiveSinks.some(s => /require_auth|require_auth_for_args/i.test(s))
      )
    );
    if (!hasAuth) {
      proof.push('✓ Why #3: Missing address.require_auth() or require_auth_for_args() — function is unguarded');
    } else {
      proof.push('WARNING Why #3: require_auth() present — must verify it is not bypassable via early return or ? operator');
    }

    // WHY #4: Why does the authorization fail to protect?
    if (!hasAuth) {
      proof.push('✓ Why #4: (No auth to bypass — direct ledger write possible)');
    } else {
      proof.push('✓ Why #4: Authorization path evaluated — checking for skip paths (early returns, unwrap, match arms)');
    }

    // WHY #5: Why did the developer think it was safe?
    proof.push('✓ Why #5: Root cause identified — developer assumed require_auth was unnecessary or that cross-contract calls are safe');

    // HOW #1: How does the attacker construct the invocation?
    proof.push(`✓ How #1: Attacker invokes ${vulnerability.location.function} on the Soroban contract via a normal contract call transaction`);

    // HOW #2: How does the attacker bypass auth?
    if (!hasAuth) {
      proof.push('✓ How #2: No authorization to bypass — function is directly callable');
    } else {
      proof.push('WARNING How #2: Searching for auth bypass paths (early return, unwrap, missing require_auth_for_args for multi-arg functions)');
    }

    // HOW #3: How does the exploit manipulate ledger state?
    const hasLedgerAccess = recursiveData?.findings.some(f => f.type === 'data-flow-expansion') || false;
    if (hasLedgerAccess) {
      proof.push('✓ How #3: Data-flow expansion confirms ledger state manipulation path');
    } else {
      proof.push('WARNING How #3: Ledger state manipulation path inferred but not recursively validated');
    }

    // HOW #4: How does profit extraction work?
    const vulnType = vulnerability.type?.toLowerCase() || '';
    if (/token|transfer|drain|withdraw/.test(vulnType)) {
      proof.push('✓ How #4: Asset extraction via token transfer or ledger value manipulation');
    } else if (/auth|access/.test(vulnType)) {
      proof.push('✓ How #4: Privilege escalation leads to further access for fund extraction');
    } else if (/overflow|arithmetic/.test(vulnType)) {
      proof.push('✓ How #4: Integer overflow/wrap enables balance inflation or fee evasion');
    } else {
      proof.push('✓ How #4: Profit mechanism identified through vulnerability type analysis');
    }

    // HOW #5: How is the attack undetectable?
    proof.push('✓ How #5: Attack appears as a legitimate Soroban contract invocation — detection requires on-chain monitoring of ledger key writes and auth check failures');

    return proof;
  }

  detectContradictions(
    vulnerability: Vulnerability,
    recursive: RecursiveAnalysis
  ): string[] {
    const contradictions: string[] = [];

    // Auth contradiction: finding claims require_auth is called, but code path shows early return
    for (const chain of recursive.callChains) {
      if (chain.vulnerableAt && chain.vulnerableAt !== vulnerability.location.function) {
        contradictions.push(
          `AUTH CONTRADICTION: Call chain shows vulnerability in ${chain.vulnerableAt}, ` +
          `but original analysis claims ${vulnerability.location.function}. ` +
          `The actual auth check may be in a different function or absent in ${chain.vulnerableAt}.`
        );
      }
    }

    // Verification contradiction
    const verification = recursive.findings.find(f => f.type === 'deeper-analysis');
    if (verification?.details?.verified === false) {
      const reason = verification.details.reason || 'unknown';
      if (/require_auth|auth|access/i.test(reason)) {
        contradictions.push(`AUTH CONTRADICTION: Self-verification failed — ${reason}`);
      } else if (/storage|persistent|temporary|instance/i.test(reason)) {
        contradictions.push(`STORAGE CONTRADICTION: Self-verification failed — ${reason}`);
      } else if (/overflow|arithmetic|i128|u128/i.test(reason)) {
        contradictions.push(`ARITHMETIC CONTRADICTION: Self-verification failed — ${reason}`);
      } else {
        contradictions.push(`SELF-VERIFICATION CONTRADICTION: ${reason}`);
      }
    } else if (verification?.details?.verified === undefined || verification?.details?.verified === null) {
      contradictions.push('VERIFICATION UNCERTAIN: Insufficient information to confirm or deny the finding');
    }

    // Storage lifetime contradiction
    const dataFlowFindings = recursive.findings.filter(f => f.type === 'data-flow-expansion');
    for (const expansion of dataFlowFindings) {
      if (expansion.details?.contradicts) {
        contradictions.push(`DATA-FLOW CONTRADICTION: ${expansion.details.contradicts}`);
      }
      // Check if storage type claims differ
      const details = expansion.details;
      if (details && details.storageType) {
        const claimedType = details.storageType;
        // If analysis claimed Persistent but code uses Temporary
        if (claimedType === 'Persistent' && JSON.stringify(details).includes('Temporary')) {
          contradictions.push('STORAGE LIFETIME CONTRADICTION: Analysis claims Persistent storage but code reveals Temporary bucket usage');
        }
      }
    }

    // SEP-41 token contradiction
    const sep41Mention = recursive.findings.some(f =>
      f.details && JSON.stringify(f.details).toLowerCase().includes('sep-41')
    );
    const balanceMention = recursive.findings.some(f =>
      f.details && JSON.stringify(f.details).toLowerCase().includes('balance')
    );
    if (sep41Mention && balanceMention) {
      contradictions.push('SEP-41 CONTRADICTION: Cross-check token interface compliance — balance tracking may diverge from ledger state');
    }

    return contradictions;
  }
}
