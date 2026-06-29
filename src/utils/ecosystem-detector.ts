import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import chalk from 'chalk';

export type Ecosystem = 'evm' | 'soroban' | 'traditional';

export interface EcosystemResult {
  ecosystem: Ecosystem;
  label: string;
}

export async function detectEcosystem(targetPath: string): Promise<EcosystemResult> {
  const resolvedTarget = path.resolve(targetPath);

  if (await detectEVM(resolvedTarget)) {
    return { ecosystem: 'evm', label: 'EVM (Solidity)' };
  }

  if (await detectSoroban(resolvedTarget)) {
    return { ecosystem: 'soroban', label: 'Soroban (Rust/WASM)' };
  }

  return { ecosystem: 'traditional', label: 'Traditional' };
}

async function detectEVM(targetPath: string): Promise<boolean> {
  const solFiles = await findFiles(targetPath, '**/*.sol');
  if (solFiles.length > 0) return true;

  const configPatterns = ['foundry.toml', 'hardhat.config.js', 'hardhat.config.ts', 'truffle-config.js'];
  for (const pattern of configPatterns) {
    const matches = await findFiles(targetPath, pattern);
    if (matches.length > 0) return true;
  }

  return false;
}

async function detectSoroban(targetPath: string): Promise<boolean> {
  const rsFiles = await findFiles(targetPath, '**/*.rs');
  for (const file of rsFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      if (content.includes('#[contract]') || content.includes('#[contractimpl]') || content.includes('soroban-sdk')) {
        return true;
      }
    } catch {
      continue;
    }
  }

  const cargoFiles = await findFiles(targetPath, '**/Cargo.toml');
  for (const file of cargoFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      if (content.includes('soroban-sdk')) {
        return true;
      }
    } catch {
      continue;
    }
  }

  return false;
}

async function findFiles(targetPath: string, pattern: string): Promise<string[]> {
  try {
    const matches = await glob(pattern, { cwd: targetPath, nodir: true, absolute: true });
    return matches;
  } catch {
    return [];
  }
}

export function printEcosystemDetection(result: EcosystemResult): void {
  console.log(chalk.green(`[+] Detected Ecosystem: ${result.label}`));
}
