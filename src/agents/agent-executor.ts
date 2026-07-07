import OpenAI from 'openai';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs/promises';
import * as path from 'path';
import { withRetry, classifyError } from '../utils/retry.js';
import { DynamicModelSelector, ModelRecommendation } from '../utils/model-selector.js';
import { getDefaultContextWindow } from '../utils/model-registry.js';
import { RLMExecutor } from './rlm/rlm-executor.js';
import { RLMCostTracker } from './rlm/rlm-cost-tracker.js';
import { RLMConfig } from './rlm/rlm-types.js';
import { ContentReplacer } from '../utils/content-replacement.js';

export interface AgentTask {
  id?: string;
  type: 'context-building' | 'vulnerability-detection' | 'poc-generation' |
        'vulnerability-pattern-extraction' | 'regression-detection' |
        'memory-safety-analysis' | 'concurrency-analysis' | 'semantic-analysis' |
        'blast-radius-analysis' | 'file-prioritization' | 'analysis-planning' |
        'custom-security-analysis';
  input: any;
  maxTokens?: number;
  model?: 'flash' | 'pro';
}

export interface AgentResult {
  success: boolean;
  output: any;
  error?: string;
  tokensUsed?: number;
  model?: string;
}

export type APIProvider = 'deepseek' | 'nvidia';

interface ProviderConfig {
  baseURL: string;
  envVar: string;
  modelMap: Record<string, string>;
  defaultModel: string;
  label: string;
}

const PROVIDER_CONFIGS: Record<APIProvider, ProviderConfig> = {
  deepseek: {
    baseURL: 'https://api.deepseek.com/v1',
    envVar: 'DEEPSEEK_API_KEY',
    modelMap: { flash: 'deepseek-chat', pro: 'deepseek-reasoner' },
    defaultModel: 'deepseek-chat',
    label: 'DeepSeek',
  },
  nvidia: {
    baseURL: 'https://integrate.api.nvidia.com/v1',
    envVar: 'NVIDIA_API_KEY',
    modelMap: { flash: 'nvidia/llama-3.1-nemotron-70b-instruct', pro: 'nvidia/llama-3.1-nemotron-70b-instruct' },
    defaultModel: 'nvidia/llama-3.1-nemotron-70b-instruct',
    label: 'NVIDIA',
  },
};

export class ClaudeExecutor {
  private client: OpenAI;
  private provider: APIProvider;
  private providerCfg: ProviderConfig;
  private tasksInProgress: Map<string, AbortController>;
  private tasksDir: string;
  private static totalTokensUsed: number = 0;
  private static tokensByTask: Map<string, number> = new Map();
  private modelSelector: DynamicModelSelector;
  private rlmExecutor: RLMExecutor | null = null;
  private rlmCostTracker: RLMCostTracker | null = null;
  private rlmConfig: RLMConfig | null = null;
  private contentReplacer: ContentReplacer;
  private static globalTargetCwd: string | undefined;

  static setGlobalTargetPath(targetPath: string): void {
    ClaudeExecutor.globalTargetCwd = path.resolve(targetPath);
  }

  setTargetPath(targetPath: string): void {
    ClaudeExecutor.setGlobalTargetPath(targetPath);
  }

  constructor(apiKey?: string, tasksDir: string = './.sandyaa/tasks', rlmConfig?: RLMConfig, provider?: APIProvider) {
    this.tasksInProgress = new Map();
    this.tasksDir = tasksDir;
    this.modelSelector = new DynamicModelSelector();
    this.contentReplacer = new ContentReplacer(path.join(path.dirname(tasksDir), 'content-cache'));

    if (rlmConfig) {
      this.rlmConfig = rlmConfig;
      this.rlmCostTracker = new RLMCostTracker(rlmConfig);
      this.rlmCostTracker.loadFromFile();
      this.rlmExecutor = new RLMExecutor(rlmConfig, this.rlmCostTracker, this);
    }

    // Auto-detect provider from env vars if not specified
    if (apiKey) {
      this.provider = provider || 'deepseek';
    } else if (process.env.NVIDIA_API_KEY) {
      this.provider = 'nvidia';
    } else if (process.env.DEEPSEEK_API_KEY) {
      this.provider = 'deepseek';
    } else {
      this.provider = provider || 'deepseek';
    }
    this.providerCfg = PROVIDER_CONFIGS[this.provider];

    const key = apiKey || process.env[this.providerCfg.envVar];
    if (!key) {
      throw new Error(
        `[-] Error: Neither DEEPSEEK_API_KEY nor NVIDIA_API_KEY is set.\n` +
        `Set one via: export DEEPSEEK_API_KEY="your-key" or export NVIDIA_API_KEY="your-key"`
      );
    }

    this.client = new OpenAI({
      apiKey: key,
      baseURL: this.providerCfg.baseURL,
    });

    console.log(`Using ${this.providerCfg.label} API (OpenAI-compatible endpoint)`);
  }

  async execute(task: AgentTask): Promise<AgentResult> {
    const taskId = task.id || uuidv4();
    const abortController = new AbortController();
    this.tasksInProgress.set(taskId, abortController);

    try {
      const result = await this.executeViaAPI(taskId, task);

      if (result.success && result.output != null) {
        const outputStr = typeof result.output === 'string'
          ? result.output
          : JSON.stringify(result.output);

        if (outputStr.length > 50_000) {
          const label = `${task.type}_${taskId}`;
          const replaced = this.contentReplacer.replaceIfLarge(outputStr, 50_000, label);
          if (replaced !== outputStr) {
            return { ...result, output: replaced };
          }
        }
      }

      return result;
    } finally {
      this.tasksInProgress.delete(taskId);
    }
  }

  /**
   * RLM-specific: execute a turn in the multi-turn loop
   */
  async executeRLMTurn(taskId: string, prompt: string, model: string, turn: number): Promise<AgentResult> {
    const task: AgentTask = {
      id: taskId,
      type: 'custom-security-analysis',
      input: { prompt, context: [{ path: '.', content: '' }] },
      model: model as 'flash' | 'pro',
    };
    return this.execute(task);
  }

  /**
   * RLM-specific: execute a sub-query during analysis
   */
  async executeRLMSubQuery(taskId: string, prompt: string, model: string): Promise<AgentResult> {
    const task: AgentTask = {
      id: taskId,
      type: 'vulnerability-pattern-extraction',
      input: { prompt, context: [{ path: '.', content: prompt }] },
      model: model as 'flash' | 'pro',
    };
    return this.execute(task);
  }

  private async executeViaAPI(taskId: string, task: AgentTask): Promise<AgentResult> {
    try {
      await fs.mkdir(this.tasksDir, { recursive: true });
      const prompt = this.buildPrompt(task);

      const taskFile = path.join(this.tasksDir, `${taskId}.md`);
      await fs.writeFile(taskFile, prompt);

      let model: 'flash' | 'pro';
      let modelReasoning: string = '';

      if (task.model) {
        model = task.model;
        modelReasoning = 'explicitly specified';
      } else {
        const files = this.extractFilesFromTask(task);
        const previousFindings = task.input?.previousFindings;
        const recommendation = await this.modelSelector.selectModel(task.type, files, previousFindings);
        model = recommendation.model as 'flash' | 'pro';
        modelReasoning = recommendation.reasoning;
        console.log(`    Model: ${model.toUpperCase()} - ${modelReasoning}`);
      }

      const resolvedModel = this.providerCfg.modelMap[model] || this.providerCfg.defaultModel;
      const maxTokens = task.maxTokens || 8000;

      // Build request with optional thinking mode
      const requestOptions: OpenAI.Chat.Completions.ChatCompletionCreateParamsNonStreaming = {
        model: resolvedModel,
        max_tokens: maxTokens,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.0,
      };

      if (model === 'pro') {
        (requestOptions as any).thinking = { type: 'enabled' };
      }

      const response = await this.client.chat.completions.create(requestOptions);

      const choice = response.choices?.[0];
      if (!choice) {
        return { success: false, output: null, error: 'No completion choices returned by DeepSeek API' };
      }

      // Extract text content, filtering out thinking blocks
      let textContent = '';
      if (choice.message?.content) {
        textContent = choice.message.content;
      }

      // Log raw response
      const rawOutputFile = path.join(this.tasksDir, `${taskId}-raw.txt`);
      await fs.writeFile(rawOutputFile, textContent);

      // Parse JSON output
      const parsed = this.parseResponse(textContent);

      const outputFile = path.join(this.tasksDir, `${taskId}-output.json`);
      await fs.writeFile(outputFile, JSON.stringify(parsed, null, 2));

      const inputTokens = response.usage?.prompt_tokens || 0;
      const outputTokens = response.usage?.completion_tokens || 0;
      const tokensUsed = inputTokens + outputTokens;

      ClaudeExecutor.totalTokensUsed += tokensUsed;
      ClaudeExecutor.tokensByTask.set(task.type,
        (ClaudeExecutor.tokensByTask.get(task.type) || 0) + tokensUsed
      );
      this.modelSelector.recordTaskResult(task.type, model, true, tokensUsed);

      return { success: true, output: parsed, tokensUsed };

    } catch (error) {
      return {
        success: false,
        output: null,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  cancel(taskId: string): void {
    const controller = this.tasksInProgress.get(taskId);
    if (controller) {
      controller.abort();
      this.tasksInProgress.delete(taskId);
    }
  }

  static getTotalTokensUsed(): number {
    return ClaudeExecutor.totalTokensUsed;
  }

  static getTokensByTask(): Map<string, number> {
    return new Map(ClaudeExecutor.tokensByTask);
  }

  static resetTokenTracking(): void {
    ClaudeExecutor.totalTokensUsed = 0;
    ClaudeExecutor.tokensByTask.clear();
  }

  static formatTokenUsage(): string {
    const total = ClaudeExecutor.totalTokensUsed;
    const byTask = ClaudeExecutor.tokensByTask;
    const contextWindow = getDefaultContextWindow();
    const contextUsagePercent = ((total / contextWindow) * 100).toFixed(2);

    let output = `Total tokens: ${total.toLocaleString()}`;
    output += `\nContext window usage: ${contextUsagePercent}% of ${(contextWindow / 1000).toFixed(0)}k`;

    if (byTask.size > 0) {
      output += '\n\nBreakdown by phase:';
      const sorted = Array.from(byTask.entries()).sort((a, b) => b[1] - a[1]);
      for (const [taskType, tokens] of sorted) {
        const percentage = ((tokens / total) * 100).toFixed(1);
        const taskName = taskType.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        output += `\n  ${taskName}: ${tokens.toLocaleString()} tokens (${percentage}%)`;
      }
    }

    return output;
  }

  private parseResponse(text: string): any {
    const codeBlockMatch = text.match(/```(?:json)?\s*\n([\s\S]*?)\n```/);
    if (codeBlockMatch) {
      try {
        return JSON.parse(codeBlockMatch[1]);
      } catch {
        // fall through
      }
    }

    const lines = text.split('\n');
    let jsonStart = -1;
    let jsonEnd = -1;
    let braceDepth = 0;
    let inJsonObject = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (/^\d+→/.test(line)) continue;

      if (!inJsonObject && line.startsWith('{')) {
        jsonStart = i;
        inJsonObject = true;
        braceDepth = 0;
      }

      if (inJsonObject) {
        for (const char of line) {
          if (char === '{') braceDepth++;
          if (char === '}') braceDepth--;
        }
        if (braceDepth === 0 && line.includes('}')) {
          jsonEnd = i;
          break;
        }
      }
    }

    if (jsonStart !== -1 && jsonEnd !== -1) {
      const jsonText = lines.slice(jsonStart, jsonEnd + 1).join('\n');
      try {
        return JSON.parse(jsonText);
      } catch {
        // fall through
      }
    }

    const jsonObjectMatch = text.match(/\{[^]*?"(?:analyses|semanticIssues|vulnerabilities|files|components|dataFlows|patterns|prioritized|language|code|setupInstructions|memoryIssues|concurrencyIssues|type|regressed)"[^]*?\}/);
    if (jsonObjectMatch) {
      try {
        return JSON.parse(jsonObjectMatch[0]);
      } catch {
        // fall through
      }
    }

    try {
      return JSON.parse(text);
    } catch {
      console.error('All JSON parsing attempts failed. Text preview:', text.substring(0, 300));
      return null;
    }
  }

  private extractFilesFromTask(task: AgentTask): string[] {
    const files: string[] = [];
    if (task.input?.files) {
      if (Array.isArray(task.input.files)) {
        files.push(...task.input.files);
      } else if (typeof task.input.files === 'object') {
        for (const file of task.input.files) {
          if (typeof file === 'string') files.push(file);
          else if (file.path) files.push(file.path);
        }
      }
    }
    if (task.input?.context?.files) {
      for (const file of task.input.context.files) {
        if (typeof file === 'string') files.push(file);
        else if (file.path) files.push(file.path);
      }
    }
    if (task.input?.targetPath && typeof task.input.targetPath === 'string') {
      files.push(task.input.targetPath);
    }
    return files;
  }

  // ─── All buildPrompt* methods preserved verbatim from original ───

  private buildPrompt(task: AgentTask): string {
    switch (task.type) {
      case 'context-building':
        return this.buildContextPrompt(task.input);
      case 'vulnerability-detection':
        return this.buildDetectionPrompt(task.input);
      case 'poc-generation':
        return this.buildPOCPrompt(task.input);
      case 'vulnerability-pattern-extraction':
        return this.buildPatternExtractionPrompt(task.input);
      case 'regression-detection':
        return this.buildRegressionDetectionPrompt(task.input);
      case 'memory-safety-analysis':
        return this.buildMemorySafetyPrompt(task.input);
      case 'concurrency-analysis':
        return this.buildConcurrencyPrompt(task.input);
      case 'semantic-analysis':
        return this.buildSemanticPrompt(task.input);
      case 'blast-radius-analysis':
        return this.buildBlastRadiusPrompt(task.input);
      case 'file-prioritization':
        return this.buildFilePrioritizationPrompt(task.input);
      case 'analysis-planning':
        return this.buildAnalysisPlanningPrompt(task.input);
      case 'custom-security-analysis':
        return this.buildCustomAnalysisPrompt(task.input);
      default:
        throw new Error(`Unknown task type: ${task.type}`);
    }
  }

  private buildBlastRadiusPrompt(input: any): string {
    const { vulnerability, context, callSites } = input;
    return `# Blast Radius Analysis

Analyze the impact and reach of this vulnerability.

## Vulnerability
${JSON.stringify(vulnerability, null, 2)}

## Context
${JSON.stringify(context, null, 2).substring(0, 5000)}

## Call Sites (${callSites.length})
${callSites.slice(0, 20).join('\n')}

## Your Task

Determine the blast radius - how far can this vulnerability's impact reach?

1. **Data Flow Impact**:
   - What data is affected by this vulnerability?
   - How far does the tainted data propagate?
   - What systems/modules use this data?

2. **User Impact**:
   - How many users could be affected?
   - What functionality is impacted?
   - Is this a critical user flow?

3. **System Impact**:
   - What systems/services are affected?
   - Can this cascade to other vulnerabilities?
   - What is the worst-case scenario?

## Output Format

\`\`\`json
{
  "affectedDataPaths": number,
  "userImpact": 0.0-1.0,
  "affectedSystems": ["system1", "system2"],
  "description": "detailed impact description"
}
\`\`\`
`;
  }

  private buildContextPrompt(input: any): string {
    const { files, targetPath, focusAreas, fileContents } = input;
    let fileContentSection = '';
    if (fileContents && typeof fileContents === 'object') {
      const entries = Object.entries(fileContents as Record<string, string>);
      const securityKeywords = ['auth', 'login', 'session', 'token', 'crypto', 'password', 'secret', 'admin', 'permission', 'role', 'access', 'sanitiz', 'valid', 'exec', 'eval', 'sql', 'query', 'upload', 'file', 'ipc', 'handler', 'route', 'api', 'middleware', 'security'];
      const scored = entries.map(([filePath, content]) => {
        const lowerPath = filePath.toLowerCase();
        const score = securityKeywords.filter(kw => lowerPath.includes(kw)).length;
        return { filePath, content: content as string, score };
      });
      scored.sort((a, b) => b.score - a.score);
      let totalChars = 0;
      const maxChars = 80_000;
      const includedFiles: { filePath: string; content: string }[] = [];
      for (const entry of scored) {
        if (totalChars + entry.content.length > maxChars && includedFiles.length > 0) break;
        includedFiles.push(entry);
        totalChars += entry.content.length;
      }
      fileContentSection = includedFiles.map(f =>
        `### ${f.filePath}\n\`\`\`\n${f.content}\n\`\`\``
      ).join('\n\n');
    }

    return `# Context Building Task

You are analyzing code for security vulnerabilities. Your job is to build deep understanding of the code.

## Target
Base path: ${targetPath}

## Files to Analyze (${files.length} files)
${files.map((f: string) => `- ${f}`).join('\n')}

${focusAreas && focusAreas.length > 0 ? `\n## Focus Areas (prioritize these)\n${focusAreas.map((f: string) => `- ${f}`).join('\n')}\n` : ''}

${fileContentSection ? `## Source Code\n\n${fileContentSection}\n` : ''}

## Instructions

1. Analyze the source code provided above thoroughly
2. For each function:
   - Identify parameters and where they come from
   - Track data flow from inputs to outputs
   - Identify dangerous operations (SQL, exec, eval, file ops, etc.)
   - Note if user input reaches dangerous operations
3. Map entry points (main, HTTP handlers, CLI args, IPC handlers)
4. Identify trust boundaries (network, filesystem, user input, process boundaries)

## Output

Respond with ONLY a JSON object (you can wrap it in markdown code blocks). Use this exact structure:
\`\`\`json
{
  "files": [
    {
      "path": "relative/path/to/file",
      "language": "javascript",
      "functions": [
        {
          "name": "functionName",
          "line": 42,
          "params": ["req", "res"],
          "userInputs": ["req.body.username"],
          "sensitiveSinks": ["db.query()"],
          "dataFlow": [
            {
              "source": "req.body.username",
              "sink": "db.query()",
              "taintPath": ["req.body.username", "username", "query"],
              "isTainted": true
            }
          ]
        }
      ]
    }
  ],
  "entryPoints": ["server.js:app.listen"],
  "trustBoundaries": [
    {
      "location": "routes/api.js:POST /login",
      "type": "user-input",
      "validation": ["none"]
    }
  ]
}
\`\`\`

Only report what you actually find in the code. Do not speculate.
`;
  }

  private serializeContext(context: any): string {
    if (!context) return '(no context available)';
    const maxChars = 120_000;
    const parts: string[] = [];

    if (context.entryPoints?.length) {
      parts.push(`Entry Points:\n${context.entryPoints.map((ep: string) => `  - ${ep}`).join('\n')}`);
    }
    if (context.trustBoundaries?.length) {
      parts.push(`Trust Boundaries:\n${JSON.stringify(context.trustBoundaries, null, 2)}`);
    }
    if (context.dataFlows?.length) {
      parts.push(`Data Flows:\n${JSON.stringify(context.dataFlows, null, 2)}`);
    }
    if (context.files?.length) {
      const filesSummary = context.files.map((f: any) => {
        const funcs = f.functions?.map((fn: any) => ({
          name: fn.name,
          line: fn.line,
          params: fn.params,
          userInputs: fn.userInputs,
          sensitiveSinks: fn.sensitiveSinks,
          dataFlow: fn.dataFlow,
        })) || [];
        return { path: f.path, language: f.language, functions: funcs, imports: f.imports, exports: f.exports };
      });
      parts.push(`Files (${context.files.length}):\n${JSON.stringify(filesSummary, null, 2)}`);
    }
    if (context.memorySafety) parts.push(`Memory Safety Analysis:\n${JSON.stringify(context.memorySafety, null, 2)}`);
    if (context.concurrency) parts.push(`Concurrency Analysis:\n${JSON.stringify(context.concurrency, null, 2)}`);
    if (context.semantic) parts.push(`Semantic Analysis:\n${JSON.stringify(context.semantic, null, 2)}`);
    if (context.customStrategies?.length) parts.push(`Custom Analysis Results:\n${JSON.stringify(context.customStrategies, null, 2)}`);

    let result = parts.join('\n\n');
    if (result.length > maxChars) {
      result = result.substring(0, maxChars);
      const lastNewline = result.lastIndexOf('\n\n');
      if (lastNewline > maxChars * 0.8) result = result.substring(0, lastNewline);
      result += '\n\n(context truncated — focus on the data above)';
    }
    return result;
  }

  private buildDetectionPrompt(input: any): string {
    const { context, verificationTask, chainTask } = input;
    if (verificationTask) return this.buildVerificationSubPrompt(verificationTask, context);
    if (chainTask) return this.buildChainSubPrompt(chainTask, context);

    return `# Autonomous Vulnerability Discovery

You are a world-class security researcher analyzing a codebase to find REAL, EXPLOITABLE bugs.

## ⚠️ CRITICAL: AVOID FALSE POSITIVES ⚠️

**DO NOT REPORT** vulnerabilities unless you can prove ALL of these with concrete evidence:
1. ✅ **Exact file path and line number** where the bug exists
2. ✅ **How attacker reaches it** - concrete entry point (HTTP endpoint, file upload, IPC, etc.)
3. ✅ **Complete data flow** - exact path from attacker input to vulnerable code
4. ✅ **Concrete attack steps** - not "could be exploited" but "here's how to exploit it"
5. ✅ **Real code snippets** - actual code from the codebase as evidence

**REJECT these immediately** (common false positives):
${this.buildFalsePositiveRules()}

## Code Context
${this.serializeContext(context)}

## Critical Instructions

**QUALITY OVER QUANTITY**: Report only HIGH-CONFIDENCE, PROVEN vulnerabilities:
- 1 real bug with complete evidence > 10 theoretical bugs
- Spend time verifying each finding before reporting
- If you can't prove it, don't report it

## Discovery Process (Think Step-by-Step)

### Phase 1: AUTONOMOUS ANALYSIS START

**YOU decide** based on the code:

1. **Identify security-critical components**:
   - Look at the code structure
   - Which modules handle sensitive data?
   - Which operations are privileged?
   - Where are the trust boundaries?

2. **Select analysis candidates** autonomously:
   - Based on code complexity
   - Based on security sensitivity
   - Based on attack surface exposure

3. **Prioritize your focus**:
   - Start with highest-risk components you identify
   - Deep-dive into those components
   - DECIDE and DO IT

### Phase 2: DEEP-DIVE & ROOT CAUSE ANALYSIS

For each component YOU selected:

1. **Trace complete data flows**:
   - Where does data originate?
   - How is it transformed?
   - Where does it end up?
   - Can attacker inject at any point?

2. **Analyze assumptions**:
   - What does the code assume?
   - Are assumptions enforced?
   - Can they be violated?

3. **Root cause thinking** — for every piece of code ask:
   - "What could THIS specific code do unexpectedly?"
   - "What assumptions is the code making, and are they always true?"
   - "As an attacker, what inputs/sequences would I try?"
   - "Can I trace a complete attack path from my control to impact?"

### Phase 3: SELF-VERIFICATION

After finding a potential vulnerability:

1. **Verify the attack path**: Trace from attacker control to impact
2. **Check for defenses**: Are there validations I missed?
3. **Verify the logic**: Does my reasoning have contradictions?
4. **Build a POC**: Can I write code that proves it?

If you can't verify all 4 steps, keep analyzing or mark as uncertain.
If you can't prove it with evidence, **don't report it**.

## ═══════════════════════════════════════════════════════════════
## GOD-LEVEL RULES - ABSOLUTE REQUIREMENTS (NO EXCEPTIONS)
## ═══════════════════════════════════════════════════════════════

**DO NOT REPORT** a vulnerability unless you have ALL of these with CONCRETE EVIDENCE:

1. ✓ **File:Line Location**: Real file path + actual line number
2. ✓ **User Control**: Attacker can trigger remotely
3. ✓ **Entry Point**: EXACT entry point
4. ✓ **Data Flow**: Complete path
5. ✓ **Attack Steps**: Concrete exploitation
6. ✓ **Code Evidence**: Real code snippets
7. ✓ **Real Impact**: What attacker achieves

**STOP AND VERIFY**: Before reporting, ask yourself:
- Can I write a concrete request that triggers this?
- Do I have the EXACT line number where the bug is?
- Can I explain step-by-step how to exploit this?
- Do I have real code snippets as evidence?

**If you answer NO to any of these, DO NOT REPORT IT.**

## Output Format

Report ONLY vulnerabilities you can prove meet ALL god-level rules:

\`\`\`json
{
  "vulnerabilities": [
    {
      "id": "vuln-unique-id",
      "type": "descriptive-name-not-generic-category",
      "severity": "critical|high|medium|low",
      "exploitability": 0.0-1.0,
      "attackerControlled": {
        "isControlled": true,
        "entryPoint": "description",
        "dataFlow": ["step1", "step2"],
        "attackPath": "description"
      },
      "blindspotCategory": "state-machine-confusion|multi-step-chain|indirect-control|race-condition|business-logic|crypto-misuse|error-path|none",
      "blindspotExplanation": "Why this would be missed",
      "location": {
        "file": "path/to/file.ext",
        "line": 123,
        "function": "functionName"
      },
      "description": "What is wrong",
      "attackVector": "Concrete exploitation steps",
      "impact": "What attacker achieves",
      "evidenceChain": [
        {
          "type": "data-flow",
          "location": "file.ext:line",
          "code": "actual code snippet",
          "reasoning": "why this is significant"
        }
      ],
      "exploitationDependencies": {
        "required": [
          {
            "type": "state|timing|etc",
            "description": "Prerequisite description",
            "feasibility": "easy|moderate|difficult|theoretical",
            "required": true
          }
        ],
        "complexity": "trivial|low|medium|high|extreme",
        "directlyExploitable": true
      },
      "reachability": {
        "isReachable": true,
        "reason": "why reachable or not"
      }
    }
  ]
}
\`\`\`

Only report what you actually find with concrete evidence. Do not speculate.`;
  }

  private buildFalsePositiveRules(): string {
    return `
❌ "Potential vulnerability if..." → REJECT: Need proof
❌ "Could lead to..." or "Might allow..." → Need concrete attack path
❌ "Missing validation" without showing exploitable impact → Not a vulnerability
❌ "Theoretical attack" without user input path → Not exploitable
❌ Generic types like "security issue" or "vulnerability" → Be specific
❌ No line numbers or "line: 0" → Must have exact location
❌ Attack vector = "N/A" or < 30 characters → Must be detailed`;
  }

  private buildVerificationSubPrompt(verificationTask: any, context: any): string {
    const { vulnerability, depth, instruction } = verificationTask;
    return `# Recursive Verification (Depth: ${depth || 0})

${instruction || 'Verify this vulnerability by re-analyzing the code independently.'}

## Vulnerability Under Review
${JSON.stringify(vulnerability, null, 2)}

## Code Context
${this.serializeContext(context)}

## Output Format

\`\`\`json
{
  "verified": true|false,
  "reason": "Detailed explanation",
  "contradictions": ["list of contradictions if any"]
}
\`\`\``;
  }

  private buildChainSubPrompt(chainTask: any, context: any): string {
    const { startingVuln, depth, instruction } = chainTask;
    return `# Vulnerability Chain Analysis (Depth: ${depth || 0})

${instruction || 'Look for other vulnerabilities that could chain with this one.'}

## Starting Vulnerability
${JSON.stringify(startingVuln, null, 2)}

## Code Context
${this.serializeContext(context)}

## Output Format

\`\`\`json
{
  "chains": [
    {
      "additionalBugs": [...],
      "exploitability": 0.0-1.0,
      "path": "combined attack path",
      "impact": "enhanced impact description"
    }
  ]
}
\`\`\``;
  }

  // The remaining build*Prompt methods are preserved identically from the original.
  // They are called via buildPrompt() and are long-but-necessary prompt templates.

  private buildPOCPrompt(input: any): string {
    const { vulnerability, currentPOC, refinementTask } = input;
    if (refinementTask) {
      return `# POC Refinement (Iteration ${refinementTask.iteration})

${refinementTask.instruction || 'Improve this proof-of-concept exploit.'}

## Vulnerability
${JSON.stringify(vulnerability, null, 2)}

## Current POC
${currentPOC ? JSON.stringify(currentPOC, null, 2) : 'No POC yet'}

## Output Format

Return the improved POC code.`;
    }

    return `# Proof of Concept Generation

Generate a working proof-of-concept exploit for this vulnerability.

## Vulnerability
${JSON.stringify(vulnerability, null, 2)}

## Instructions

Create a complete, working POC that:
1. Sets up the required environment
2. Reproduces the vulnerability
3. Demonstrates the impact
4. Includes assertions verifying success

## Output Format

\`\`\`json
{
  "language": "python|javascript|bash|etc",
  "code": "complete exploit code",
  "setupInstructions": "how to run this",
  "testSteps": ["step1", "step2"],
  "expectedImpact": "what the POC demonstrates",
  "prerequisitesHandled": {
    "exploitationDependencies": "...",
    "reachability": "...",
    "attackChain": "..."
  }
}
\`\`\``;
  }

  private buildPatternExtractionPrompt(input: any): string {
    return `# Vulnerability Pattern Extraction

Extract patterns from known vulnerabilities to identify similar issues in other code.

## Input Data
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

\`\`\`json
{
  "patterns": [
    {
      "type": "pattern-category",
      "description": "pattern description",
      "codePattern": "regex-like pattern",
      "riskLevel": "critical|high|medium|low",
      "examples": ["example1"]
    }
  ]
}
\`\`\``;
  }

  private buildRegressionDetectionPrompt(input: any): string {
    return `# Regression Detection

Analyze if previously fixed vulnerabilities have regressed.

## Input
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

\`\`\`json
{
  "regressions": [
    {
      "vulnerabilityId": "...",
      "similarity": 0.0-1.0,
      "type": "exact|partial|related",
      "location": {
        "file": "...",
        "line": 123
      }
    }
  ]
}
\`\`\``;
  }

  private buildMemorySafetyPrompt(input: any): string {
    return `# Memory Safety Analysis

Analyze the code for memory safety vulnerabilities.

## Context
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

\`\`\`json
{
  "memoryIssues": []
}
\`\`\``;
  }

  private buildConcurrencyPrompt(input: any): string {
    return `# Concurrency Analysis

Analyze the code for concurrency vulnerabilities (race conditions, TOCTOU, etc.).

## Context
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

\`\`\`json
{
  "concurrencyIssues": []
}
\`\`\``;
  }

  private buildSemanticPrompt(input: any): string {
    return `# Semantic Analysis

Analyze the code for semantic vulnerabilities (business logic flaws, state machine issues, etc.).

## Context
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

\`\`\`json
{
  "semanticIssues": []
}
\`\`\``;
  }

  private buildFilePrioritizationPrompt(input: any): string {
    return `# File Prioritization

Prioritize files for security analysis based on risk factors.

## Input
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

\`\`\`json
{
  "prioritized": []
}
\`\`\``;
  }

  private buildAnalysisPlanningPrompt(input: any): string {
    return `# Analysis Planning

Plan the security analysis approach for this codebase.

## Input
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

\`\`\`json
{
  "plan": []
}
\`\`\``;
  }

  private buildCustomAnalysisPrompt(input: any): string {
    return `# Custom Security Analysis

Perform a custom security analysis.

## Input
${JSON.stringify(input, null, 2).substring(0, 10000)}

## Output Format

Return detailed analysis findings in JSON format.`;
  }
}
