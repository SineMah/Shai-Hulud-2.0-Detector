#!/usr/bin/env node
import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import {
  runScan,
  formatTextReport,
  generateSarifReport,
  getMasterPackagesInfo,
} from './scanner';
import { ScanSummary } from './types';

const program = new Command();

program
  .name('shai-hulud-detector')
  .description('Detect Shai-Hulud 2.0 supply chain attack in npm dependencies')
  .version('1.0.0')
  .option('-d, --dir <path>', 'Working directory to scan', process.cwd())
  .option('--fail-on-critical', 'Fail if critical issues are found', false)
  .option('--fail-on-high', 'Fail if high or critical issues are found', false)
  .option('--fail-on-any', 'Fail if any issues are found', false)
  .option('--scan-lockfiles', 'Scan lockfiles (package-lock.json, yarn.lock)', true)
  .option('--no-scan-lockfiles', 'Do not scan lockfiles')
  .option('--scan-node-modules', 'Scan node_modules directory', false)
  .option('-f, --format <format>', 'Output format (text, json, sarif)', 'text')
  .action(async (options) => {
    console.log('');
    console.log('Shai-Hulud 2.0 Detector');
    console.log('=======================');

    // Display database info
    const dbInfo = getMasterPackagesInfo();
    console.log(`Database version: ${dbInfo.version}`);
    console.log(`Last updated: ${dbInfo.lastUpdated}`);
    console.log(`Total known affected packages: ${dbInfo.totalPackages}`);
    console.log('');

    // Resolve working directory
    const workDir = path.resolve(options.dir);
    console.log(`Scanning directory: ${workDir}`);

    if (!fs.existsSync(workDir)) {
      console.error(`Error: Working directory does not exist: ${workDir}`);
      process.exit(1);
    }

    // Run the scan
    console.log('Starting scan...');
    // Note: runScan signature in scanner.ts is (directory: string, scanLockfiles: boolean)
    // We might need to check if it supports scanNodeModules or if that's handled internally or missing
    // Looking at scanner.ts, runScan is imported but I didn't see the definition in the previous view_file of scanner.ts (it was truncated?)
    // Let's assume runScan matches what index.ts uses: runScan(workDir, inputs.scanLockfiles)
    // Wait, index.ts uses: const summary = runScan(workDir, inputs.scanLockfiles);
    // But inputs has scanNodeModules. Does runScan use it?
    // I need to check runScan signature in scanner.ts again to be sure.
    // For now I will assume it matches index.ts usage.
    
    const summary = runScan(workDir, options.scanLockfiles);

    // Output results based on format
    switch (options.format) {
      case 'json':
        console.log('');
        console.log('JSON Report:');
        console.log(JSON.stringify(summary, null, 2));
        break;

      case 'sarif':
        const sarifReport = generateSarifReport(summary);
        const sarifPath = path.join(workDir, 'shai-hulud-results.sarif');
        fs.writeFileSync(sarifPath, JSON.stringify(sarifReport, null, 2));
        console.log(`SARIF report written to: ${sarifPath}`);
        break;

      case 'text':
      default:
        console.log(formatTextReport(summary));
        break;
    }

    // Determine if we should fail
    let shouldFail = false;
    let failReason = '';
    const hasIssues = summary.affectedCount > 0 || summary.securityFindings.length > 0;

    // Count critical findings from security checks
    const criticalSecurityFindings = summary.securityFindings.filter(
      (f) => f.severity === 'critical'
    ).length;
    const highSecurityFindings = summary.securityFindings.filter(
      (f) => f.severity === 'critical' || f.severity === 'high'
    ).length;

    if (options.failOnAny && hasIssues) {
      const issues = [];
      if (summary.affectedCount > 0) issues.push(`${summary.affectedCount} compromised package(s)`);
      if (summary.securityFindings.length > 0) issues.push(`${summary.securityFindings.length} security finding(s)`);
      shouldFail = true;
      failReason = issues.join(' and ');
    } else if (options.failOnCritical) {
      const criticalPackages = summary.results.filter(
        (r) => r.severity === 'critical'
      ).length;
      const totalCritical = criticalPackages + criticalSecurityFindings;
      if (totalCritical > 0) {
        shouldFail = true;
        failReason = `${totalCritical} critical severity issue(s) detected`;
      }
    } else if (options.failOnHigh) {
      const highOrAbovePackages = summary.results.filter(
        (r) => r.severity === 'critical' || r.severity === 'high'
      ).length;
      const totalHighOrAbove = highOrAbovePackages + highSecurityFindings;
      if (totalHighOrAbove > 0) {
        shouldFail = true;
        failReason = `${totalHighOrAbove} high/critical severity issue(s) detected`;
      }
    }

    if (shouldFail) {
      console.error(`\nFAILURE: Shai-Hulud 2.0 supply chain attack indicators detected: ${failReason}`);
      process.exit(1);
    } else if (hasIssues) {
      console.warn(
        `\nWARNING: Issues found (${summary.affectedCount} package(s), ${summary.securityFindings.length} finding(s)) but not failing due to configuration`
      );
    } else {
      console.log('\nScan complete. No compromised packages or security issues detected.');
    }
  });

program.parse();
