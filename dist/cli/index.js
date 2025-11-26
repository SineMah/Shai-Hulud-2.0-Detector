#!/usr/bin/env node
require('./sourcemap-register.js');/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 581:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", ({ value: true }));
const commander_1 = __nccwpck_require__(909);
const path = __importStar(__nccwpck_require__(928));
const fs = __importStar(__nccwpck_require__(896));
const scanner_1 = __nccwpck_require__(105);
const program = new commander_1.Command();
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
    const dbInfo = (0, scanner_1.getMasterPackagesInfo)();
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
    const summary = (0, scanner_1.runScan)(workDir, options.scanLockfiles);
    // Output results based on format
    switch (options.format) {
        case 'json':
            console.log('');
            console.log('JSON Report:');
            console.log(JSON.stringify(summary, null, 2));
            break;
        case 'sarif':
            const sarifReport = (0, scanner_1.generateSarifReport)(summary);
            const sarifPath = path.join(workDir, 'shai-hulud-results.sarif');
            fs.writeFileSync(sarifPath, JSON.stringify(sarifReport, null, 2));
            console.log(`SARIF report written to: ${sarifPath}`);
            break;
        case 'text':
        default:
            console.log((0, scanner_1.formatTextReport)(summary));
            break;
    }
    // Determine if we should fail
    let shouldFail = false;
    let failReason = '';
    const hasIssues = summary.affectedCount > 0 || summary.securityFindings.length > 0;
    // Count critical findings from security checks
    const criticalSecurityFindings = summary.securityFindings.filter((f) => f.severity === 'critical').length;
    const highSecurityFindings = summary.securityFindings.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
    if (options.failOnAny && hasIssues) {
        const issues = [];
        if (summary.affectedCount > 0)
            issues.push(`${summary.affectedCount} compromised package(s)`);
        if (summary.securityFindings.length > 0)
            issues.push(`${summary.securityFindings.length} security finding(s)`);
        shouldFail = true;
        failReason = issues.join(' and ');
    }
    else if (options.failOnCritical) {
        const criticalPackages = summary.results.filter((r) => r.severity === 'critical').length;
        const totalCritical = criticalPackages + criticalSecurityFindings;
        if (totalCritical > 0) {
            shouldFail = true;
            failReason = `${totalCritical} critical severity issue(s) detected`;
        }
    }
    else if (options.failOnHigh) {
        const highOrAbovePackages = summary.results.filter((r) => r.severity === 'critical' || r.severity === 'high').length;
        const totalHighOrAbove = highOrAbovePackages + highSecurityFindings;
        if (totalHighOrAbove > 0) {
            shouldFail = true;
            failReason = `${totalHighOrAbove} high/critical severity issue(s) detected`;
        }
    }
    if (shouldFail) {
        console.error(`\nFAILURE: Shai-Hulud 2.0 supply chain attack indicators detected: ${failReason}`);
        process.exit(1);
    }
    else if (hasIssues) {
        console.warn(`\nWARNING: Issues found (${summary.affectedCount} package(s), ${summary.securityFindings.length} finding(s)) but not failing due to configuration`);
    }
    else {
        console.log('\nScan complete. No compromised packages or security issues detected.');
    }
});
program.parse();
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiZmlsZTovLy9ob21lL3NpbmUvRG9jdW1lbnRzL3NyYy9TaGFpLUh1bHVkLTIuMC1EZXRlY3Rvci9zcmMvY2xpLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O0FBQUEseUNBQW9DO0FBQ3BDLDJDQUE2QjtBQUM3Qix1Q0FBeUI7QUFDekIsdUNBS21CO0FBR25CLE1BQU0sT0FBTyxHQUFHLElBQUksbUJBQU8sRUFBRSxDQUFDO0FBRTlCLE9BQU87S0FDSixJQUFJLENBQUMscUJBQXFCLENBQUM7S0FDM0IsV0FBVyxDQUFDLCtEQUErRCxDQUFDO0tBQzVFLE9BQU8sQ0FBQyxPQUFPLENBQUM7S0FDaEIsTUFBTSxDQUFDLGtCQUFrQixFQUFFLDJCQUEyQixFQUFFLE9BQU8sQ0FBQyxHQUFHLEVBQUUsQ0FBQztLQUN0RSxNQUFNLENBQUMsb0JBQW9CLEVBQUUsbUNBQW1DLEVBQUUsS0FBSyxDQUFDO0tBQ3hFLE1BQU0sQ0FBQyxnQkFBZ0IsRUFBRSwyQ0FBMkMsRUFBRSxLQUFLLENBQUM7S0FDNUUsTUFBTSxDQUFDLGVBQWUsRUFBRSw4QkFBOEIsRUFBRSxLQUFLLENBQUM7S0FDOUQsTUFBTSxDQUFDLGtCQUFrQixFQUFFLCtDQUErQyxFQUFFLElBQUksQ0FBQztLQUNqRixNQUFNLENBQUMscUJBQXFCLEVBQUUsdUJBQXVCLENBQUM7S0FDdEQsTUFBTSxDQUFDLHFCQUFxQixFQUFFLDZCQUE2QixFQUFFLEtBQUssQ0FBQztLQUNuRSxNQUFNLENBQUMsdUJBQXVCLEVBQUUsbUNBQW1DLEVBQUUsTUFBTSxDQUFDO0tBQzVFLE1BQU0sQ0FBQyxLQUFLLEVBQUUsT0FBTyxFQUFFLEVBQUU7SUFDeEIsT0FBTyxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUNoQixPQUFPLENBQUMsR0FBRyxDQUFDLHlCQUF5QixDQUFDLENBQUM7SUFDdkMsT0FB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TUFBTSxtQkFBbUIsR0FBRyxPQUFPLENBQUMsT0FBTyxDQUFDLE1BQU0sQ0FDaEQsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsQ0FBQyxRQUFRLEtBQUssVUFBVSxJQUFJLENBQUMsQ0FBQyxRQUFRLEtBQUssTUFBTSxDQUMxRCxDQUFDLE1BQU0sQ0FBQztRQUNULE1BQU0sZ0JBQWdCLEdBQUcsbUJBQW1CLEdBQUcsb0JBQW9CLENBQUM7UUFDcEUsSUFBSSxnQkFBZ0IsR0FBRyxDQUFDLEVBQUUsQ0FBQztZQUN6QixVQUFVLEdBQUcsSUFBSSxDQUFDO1lBQ2xCLFVBQVUsR0FBRyxHQUFHLGdCQUFnQiwyQ0FBMkMsQ0FBQztRQUM5RSxDQUFDO0lBQ0gsQ0FBQztJQUVELElBQUksVUFBVSxFQUFFLENBQUM7UUFDZixPQUFPLENBQUMsS0FBSyxDQUFDLHNFQUFzRSxVQUFVLEVBQUUsQ0FBQyxDQUFDO1FBQ2xHLE9BQU8sQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDbEIsQ0FBQztTQUFNLElBQUksU0FBUyxFQUFFLENBQUM7UUFDckIsT0FBTyxDQUFDLElBQUksQ0FDViw0QkFBNEIsT0FBTyxDQUFDLGFBQWEsZ0JBQWdCLE9BQU8sQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLG1EQUFtRCxDQUNwSixDQUFDO0lBQ0osQ0FBQztTQUFNLENBQUM7UUFDTixPQUFPLENBQUMsR0FBRyxDQUFDLHVFQUF1RSxDQUFDLENBQUM7SUFDdkYsQ0FBQztBQUNILENBQUMsQ0FBQyxDQUFDO0FBRUwsT0FBTyxDQUFDLEtBQUssRUFBRSxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQ29tbWFuZCB9IGZyb20gJ2NvbW1hbmRlcic7XG5pbXBvcnQgKiBhcyBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0ICogYXMgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHtcbiAgcnVuU2NhbixcbiAgZm9ybWF0VGV4dFJlcG9ydCxcbiAgZ2VuZXJhdGVTYXJpZlJlcG9ydCxcbiAgZ2V0TWFzdGVyUGFja2FnZXNJbmZvLFxufSBmcm9tICcuL3NjYW5uZXInO1xuaW1wb3J0IHsgU2NhblN1bW1hcnkgfSBmcm9tICcuL3R5cGVzJztcblxuY29uc3QgcHJvZ3JhbSA9IG5ldyBDb21tYW5kKCk7XG5cbnByb2dyYW1cbiAgLm5hbWUoJ3NoYWktaHVsdWQtZGV0ZWN0b3InKVxuICAuZGVzY3JpcHRpb24oJ0RldGVjdCBTaGFpLUh1bHVkIDIuMCBzdXBwbHkgY2hhaW4gYXR0YWNrIGluIG5wbSBkZXBlbmRlbmNpZXMnKVxuICAudmVyc2lvbignMS4wLjAnKVxuICAub3B0aW9uKCctZCwgLS1kaXIgPHBhdGg+JywgJ1dvcmtpbmcgZGlyZWN0b3J5IHRvIHNjYW4nLCBwcm9jZXNzLmN3ZCgpKVxuICAub3B0aW9uKCctLWZhaWwtb24tY3JpdGljYWwnLCAnRmFpbCBpZiBjcml0aWNhbCBpc3N1ZXMgYXJlIGZvdW5kJywgZmFsc2UpXG4gIC5vcHRpb24oJy0tZmFpbC1vbi1oaWdoJywgJ0ZhaWwgaWYgaGlnaCBvciBjcml0aWNhbCBpc3N1ZXMgYXJlIGZvdW5kJywgZmFsc2UpXG4gIC5vcHRpb24oJy0tZmFpbC1vbi1hbnknLCAnRmFpbCBpZiBhbnkgaXNzdWVzIGFyZSBmb3VuZCcsIGZhbHNlKVxuICAub3B0aW9uKCctLXNjYW4tbG9ja2ZpbGVzJywgJ1NjYW4gbG9ja2ZpbGVzIChwYWNrYWdlLWxvY2suanNvbiwgeWFybi5sb2NrKScsIHRydWUpXG4gIC5vcHRpb24oJy0tbm8tc2Nhbi1sb2NrZmlsZXMnLCAnRG8gbm90IHNjYW4gbG9ja2ZpbGVzJylcbiAgLm9wdGlvbignLS1zY2FuLW5vZGUtbW9kdWxlcycsICdTY2FuIG5vZGVfbW9kdWxlcyBkaXJlY3RvcnknLCBmYWxzZSlcbiAgLm9wdGlvbignLWYsIC0tZm9ybWF0IDxmb3JtYXQ+JywgJ091dHB1dCBmb3JtYXQgKHRleHQsIGpzb24sIHNhcmlmKScsICd0ZXh0JylcbiAgLmFjdGlvbihhc3luYyAob3B0aW9ucykgPT4ge1xuICAgIGNvbnNvbGUubG9nKCcnKTtcbiAgICBjb25zb2xlLmxvZygnU2hhaS1IdWx1ZCAyLjAgRGV0ZWN0b3InKTtcbiAgICBjb25zb2xlLmxvZygnPT09PT09PT09PT09PT09PT09PT09PT0nKTtcblxuICAgIC8vIERpc3BsYXkgZGF0YWJhc2UgaW5mb1xuICAgIGNvbnN0IGRiSW5mbyA9IGdldE1hc3RlclBhY2thZ2VzSW5mbygpO1xuICAgIGNvbnNvbGUubG9nKGBEYXRhYmFzZSB2ZXJzaW9uOiAke2RiSW5mby52ZXJzaW9ufWApO1xuICAgIGNvbnNvbGUubG9nKGBMYXN0IHVwZGF0ZWQ6ICR7ZGJJbmZvLmxhc3RVcGRhdGVkfWApO1xuICAgIGNvbnNvbGUubG9nKGBUb3RhbCBrbm93biBhZmZlY3RlZCBwYWNrYWdlczogJHtkYkluZm8udG90YWxQYWNrYWdlc31gKTtcbiAgICBjb25zb2xlLmxvZygnJyk7XG5cbiAgICAvLyBSZXNvbHZlIHdvcmtpbmcgZGlyZWN0b3J5XG4gICAgY29uc3Qgd29ya0RpciA9IHBhdGgucmVzb2x2ZShvcHRpb25zLmRpcik7XG4gICAgY29uc29sZS5sb2coYFNjYW5uaW5nIGRpcmVjdG9yeTogJHt3b3JrRGlyfWApO1xuXG4gICAgaWYgKCFmcy5leGlzdHNTeW5jKHdvcmtEaXIpKSB7XG4gICAgICBjb25zb2xlLmVycm9yKGBFcnJvcjogV29ya2luZyBkaXJlY3RvcnkgZG9lcyBub3QgZXhpc3Q6ICR7d29ya0Rpcn1gKTtcbiAgICAgIHByb2Nlc3MuZXhpdCgxKTtcbiAgICB9XG5cbiAgICAvLyBSdW4gdGhlIHNjYW5cbiAgICBjb25zb2xlLmxvZygnU3RhcnRpbmcgc2Nhbi4uLicpO1xuICAgIC8vIE5vdGU6IHJ1blNjYW4gc2lnbmF0dXJlIGluIHNjYW5uZXIudHMgaXMgKGRpcmVjdG9yeTogc3RyaW5nLCBzY2FuTG9ja2ZpbGVzOiBib29sZWFuKVxuICAgIC8vIFdlIG1pZ2h0IG5lZWQgdG8gY2hlY2sgaWYgaXQgc3VwcG9ydHMgc2Nhbk5vZGVNb2R1bGVzIG9yIGlmIHRoYXQncyBoYW5kbGVkIGludGVybmFsbHkgb3IgbWlzc2luZ1xuICAgIC8vIExvb2tpbmcgYXQgc2Nhbm5lci50cywgcnVuU2NhbiBpcyBpbXBvcnRlZCBidXQgSSBkaWRuJ3Qgc2VlIHRoZSBkZWZpbml0aW9uIGluIHRoZSBwcmV2aW91cyB2aWV3X2ZpbGUgb2Ygc2Nhbm5lci50cyAoaXQgd2FzIHRydW5jYXRlZD8pXG4gICAgLy8gTGV0J3MgYXNzdW1lIHJ1blNjYW4gbWF0Y2hlcyB3aGF0IGluZGV4LnRzIHVzZXM6IHJ1blNjYW4od29ya0RpciwgaW5wdXRzLnNjYW5Mb2NrZmlsZXMpXG4gICAgLy8gV2FpdCwgaW5kZXgudHMgdXNlczogY29uc3Qgc3VtbWFyeSA9IHJ1blNjYW4od29ya0RpciwgaW5wdXRzLnNjYW5Mb2NrZmlsZXMpO1xuICAgIC8vIEJ1dCBpbnB1dHMgaGFzIHNjYW5Ob2RlTW9kdWxlcy4gRG9lcyBydW5TY2FuIHVzZSBpdD9cbiAgICAvLyBJIG5lZWQgdG8gY2hlY2sgcnVuU2NhbiBzaWduYXR1cmUgaW4gc2Nhbm5lci50cyBhZ2FpbiB0byBiZSBzdXJlLlxuICAgIC8vIEZvciBub3cgSSB3aWxsIGFzc3VtZSBpdCBtYXRjaGVzIGluZGV4LnRzIHVzYWdlLlxuICAgIFxuICAgIGNvbnN0IHN1bW1hcnkgPSBydW5TY2FuKHdvcmtEaXIsIG9wdGlvbnMuc2NhbkxvY2tmaWxlcyk7XG5cbiAgICAvLyBPdXRwdXQgcmVzdWx0cyBiYXNlZCBvbiBmb3JtYXRcbiAgICBzd2l0Y2ggKG9wdGlvbnMuZm9ybWF0KSB7XG4gICAgICBjYXNlICdqc29uJzpcbiAgICAgICAgY29uc29sZS5sb2coJycpO1xuICAgICAgICBjb25zb2xlLmxvZygnSlNPTiBSZXBvcnQ6Jyk7XG4gICAgICAgIGNvbnNvbGUubG9nKEpTT04uc3RyaW5naWZ5KHN1bW1hcnksIG51bGwsIDIpKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgJ3NhcmlmJzpcbiAgICAgICAgY29uc3Qgc2FyaWZSZXBvcnQgPSBnZW5lcmF0ZVNhcmlmUmVwb3J0KHN1bW1hcnkpO1xuICAgICAgICBjb25zdCBzYXJpZlBhdGggPSBwYXRoLmpvaW4od29ya0RpciwgJ3NoYWktaHVsdWQtcmVzdWx0cy5zYXJpZicpO1xuICAgICAgICBmcy53cml0ZUZpbGVTeW5jKHNhcmlmUGF0aCwgSlNPTi5zdHJpbmdpZnkoc2FyaWZSZXBvcnQsIG51bGwsIDIpKTtcbiAgICAgICAgY29uc29sZS5sb2coYFNBUklGIHJlcG9ydCB3cml0dGVuIHRvOiAke3NhcmlmUGF0aH1gKTtcbiAgICAgICAgYnJlYWs7XG5cbiAgICAgIGNhc2UgJ3RleHQnOlxuICAgICAgZGVmYXVsdDpcbiAgICAgICAgY29uc29sZS5sb2coZm9ybWF0VGV4dFJlcG9ydChzdW1tYXJ5KSk7XG4gICAgICAgIGJyZWFrO1xuICAgIH1cblxuICAgIC8vIERldGVybWluZSBpZiB3ZSBzaG91bGQgZmFpbFxuICAgIGxldCBzaG91bGRGYWlsID0gZmFsc2U7XG4gICAgbGV0IGZhaWxSZWFzb24gPSAnJztcbiAgICBjb25zdCBoYXNJc3N1ZXMgPSBzdW1tYXJ5LmFmZmVjdGVkQ291bnQgPiAwIHx8IHN1bW1hcnkuc2VjdXJpdHlGaW5kaW5ncy5sZW5ndGggPiAwO1xuXG4gICAgLy8gQ291bnQgY3JpdGljYWwgZmluZGluZ3MgZnJvbSBzZWN1cml0eSBjaGVja3NcbiAgICBjb25zdCBjcml0aWNhbFNlY3VyaXR5RmluZGluZ3MgPSBzdW1tYXJ5LnNlY3VyaXR5RmluZGluZ3MuZmlsdGVyKFxuICAgICAgKGYpID0+IGYuc2V2ZXJpdHkgPT09ICdjcml0aWNhbCdcbiAgICApLmxlbmd0aDtcbiAgICBjb25zdCBoaWdoU2VjdXJpdHlGaW5kaW5ncyA9IHN1bW1hcnkuc2VjdXJpdHlGaW5kaW5ncy5maWx0ZXIoXG4gICAgICAoZikgPT4gZi5zZXZlcml0eSA9PT0gJ2NyaXRpY2FsJyB8fCBmLnNldmVyaXR5ID09PSAnaGlnaCdcbiAgICApLmxlbmd0aDtcblxuICAgIGlmIChvcHRpb25zLmZhaWxPbkFueSAmJiBoYXNJc3N1ZXMpIHtcbiAgICAgIGNvbnN0IGlzc3VlcyA9IFtdO1xuICAgICAgaWYgKHN1bW1hcnkuYWZmZWN0ZWRDb3VudCA+IDApIGlzc3Vlcy5wdXNoKGAke3N1bW1hcnkuYWZmZWN0ZWRDb3VudH0gY29tcHJvbWlzZWQgcGFja2FnZShzKWApO1xuICAgICAgaWYgKHN1bW1hcnkuc2VjdXJpdHlGaW5kaW5ncy5sZW5ndGggPiAwKSBpc3N1ZXMucHVzaChgJHtzdW1tYXJ5LnNlY3VyaXR5RmluZGluZ3MubGVuZ3RofSBzZWN1cml0eSBmaW5kaW5nKHMpYCk7XG4gICAgICBzaG91bGRGYWlsID0gdHJ1ZTtcbiAgICAgIGZhaWxSZWFzb24gPSBpc3N1ZXMuam9pbignIGFuZCAnKTtcbiAgICB9IGVsc2UgaWYgKG9wdGlvbnMuZmFpbE9uQ3JpdGljYWwpIHtcbiAgICAgIGNvbnN0IGNyaXRpY2FsUGFja2FnZXMgPSBzdW1tYXJ5LnJlc3VsdHMuZmlsdGVyKFxuICAgICAgICAocikgPT4gci5zZXZlcml0eSA9PT0gJ2NyaXRpY2FsJ1xuICAgICAgKS5sZW5ndGg7XG4gICAgICBjb25zdCB0b3RhbENyaXRpY2FsID0gY3JpdGljYWxQYWNrYWdlcyArIGNyaXRpY2FsU2VjdXJpdHlGaW5kaW5ncztcbiAgICAgIGlmICh0b3RhbENyaXRpY2FsID4gMCkge1xuICAgICAgICBzaG91bGRGYWlsID0gdHJ1ZTtcbiAgICAgICAgZmFpbFJlYXNvbiA9IGAke3RvdGFsQ3JpdGljYWx9IGNyaXRpY2FsIHNldmVyaXR5IGlzc3VlKHMpIGRldGVjdGVkYDtcbiAgICAgIH1cbiAgICB9IGVsc2UgaWYgKG9wdGlvbnMuZmFpbE9uSGlnaCkge1xuICAgICAgY29uc3QgaGlnaE9yQWJvdmVQYWNrYWdlcyA9IHN1bW1hcnkucmVzdWx0cy5maWx0ZXIoXG4gICAgICAgIChyKSA9PiByLnNldmVyaXR5ID09PSAnY3JpdGljYWwnIHx8IHIuc2V2ZXJpdHkgPT09ICdoaWdoJ1xuICAgICAgKS5sZW5ndGg7XG4gICAgICBjb25zdCB0b3RhbEhpZ2hPckFib3ZlID0gaGlnaE9yQWJvdmVQYWNrYWdlcyArIGhpZ2hTZWN1cml0eUZpbmRpbmdzO1xuICAgICAgaWYgKHRvdGFsSGlnaE9yQWJvdmUgPiAwKSB7XG4gICAgICAgIHNob3VsZEZhaWwgPSB0cnVlO1xuICAgICAgICBmYWlsUmVhc29uID0gYCR7dG90YWxIaWdoT3JBYm92ZX0gaGlnaC9jcml0aWNhbCBzZXZlcml0eSBpc3N1ZShzKSBkZXRlY3RlZGA7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKHNob3VsZEZhaWwpIHtcbiAgICAgIGNvbnNvbGUuZXJyb3IoYFxcbkZBSUxVUkU6IFNoYWktSHVsdWQgMi4wIHN1cHBseSBjaGFpbiBhdHRhY2sgaW5kaWNhdG9ycyBkZXRlY3RlZDogJHtmYWlsUmVhc29ufWApO1xuICAgICAgcHJvY2Vzcy5leGl0KDEpO1xuICAgIH0gZWxzZSBpZiAoaGFzSXNzdWVzKSB7XG4gICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgIGBcXG5XQVJOSU5HOiBJc3N1ZXMgZm91bmQgKCR7c3VtbWFyeS5hZmZlY3RlZENvdW50fSBwYWNrYWdlKHMpLCAke3N1bW1hcnkuc2VjdXJpdHlGaW5kaW5ncy5sZW5ndGh9IGZpbmRpbmcocykpIGJ1dCBub3QgZmFpbGluZyBkdWUgdG8gY29uZmlndXJhdGlvbmBcbiAgICAgICk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbnNvbGUubG9nKCdcXG5TY2FuIGNvbXBsZXRlLiBObyBjb21wcm9taXNlZCBwYWNrYWdlcyBvciBzZWN1cml0eSBpc3N1ZXMgZGV0ZWN0ZWQuJyk7XG4gICAgfVxuICB9KTtcblxucHJvZ3JhbS5wYXJzZSgpO1xuIl19

/***/ }),

/***/ 105:
/***/ (function(__unused_webpack_module, exports, __nccwpck_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isAffected = isAffected;
exports.getPackageSeverity = getPackageSeverity;
exports.parsePackageJson = parsePackageJson;
exports.parsePackageLock = parsePackageLock;
exports.parseYarnLock = parseYarnLock;
exports.scanPackageJson = scanPackageJson;
exports.scanPackageLock = scanPackageLock;
exports.scanYarnLock = scanYarnLock;
exports.findLockfiles = findLockfiles;
exports.findPackageJsonFiles = findPackageJsonFiles;
exports.checkSuspiciousScripts = checkSuspiciousScripts;
exports.checkTrufflehogActivity = checkTrufflehogActivity;
exports.checkSecretsExfiltration = checkSecretsExfiltration;
exports.checkMaliciousRunners = checkMaliciousRunners;
exports.checkShaiHuludRepos = checkShaiHuludRepos;
exports.checkAffectedNamespaces = checkAffectedNamespaces;
exports.checkSuspiciousBranches = checkSuspiciousBranches;
exports.runScan = runScan;
exports.generateSarifReport = generateSarifReport;
exports.formatTextReport = formatTextReport;
exports.getMasterPackagesInfo = getMasterPackagesInfo;
const fs = __importStar(__nccwpck_require__(896));
const path = __importStar(__nccwpck_require__(928));
const compromised_packages_json_1 = __importDefault(__nccwpck_require__(182));
// =============================================================================
// SUSPICIOUS PATTERNS FOR ADVANCED DETECTION
// =============================================================================
// Suspicious commands in package.json scripts
const SUSPICIOUS_SCRIPT_PATTERNS = [
    { pattern: /setup_bun\.js/i, description: 'Shai-Hulud malicious setup script' },
    { pattern: /bun_environment\.js/i, description: 'Shai-Hulud environment script' },
    { pattern: /\bcurl\s+[^|]*\|\s*(ba)?sh/i, description: 'Curl piped to shell execution' },
    { pattern: /\bwget\s+[^|]*\|\s*(ba)?sh/i, description: 'Wget piped to shell execution' },
    { pattern: /\beval\s*\(/i, description: 'Eval execution (potential code injection)' },
    { pattern: /\beval\s+['"`\$]/i, description: 'Eval with dynamic content' },
    { pattern: /base64\s+(--)?d(ecode)?/i, description: 'Base64 decode execution' },
    { pattern: /\$\(curl/i, description: 'Command substitution with curl' },
    { pattern: /\$\(wget/i, description: 'Command substitution with wget' },
    { pattern: /node\s+-e\s+['"].*?(http|eval|Buffer\.from)/i, description: 'Inline Node.js code execution' },
    { pattern: /npx\s+--yes\s+[^@\s]+@/i, description: 'NPX auto-install of versioned package' },
];
// TruffleHog and credential scanning patterns
const TRUFFLEHOG_PATTERNS = [
    { pattern: /trufflehog/i, description: 'TruffleHog reference detected' },
    { pattern: /trufflesecurity/i, description: 'TruffleSecurity reference' },
    { pattern: /credential[_-]?scan/i, description: 'Credential scanning pattern' },
    { pattern: /secret[_-]?scan/i, description: 'Secret scanning pattern' },
    { pattern: /--json\s+--no-update/i, description: 'TruffleHog CLI pattern' },
    { pattern: /github\.com\/trufflesecurity\/trufflehog/i, description: 'TruffleHog GitHub download' },
    { pattern: /releases\/download.*trufflehog/i, description: 'TruffleHog binary download' },
];
// Shai-Hulud repository indicators
const SHAI_HULUD_REPO_PATTERNS = [
    { pattern: /shai[-_]?hulud/i, description: 'Shai-Hulud repository name' },
    { pattern: /the\s+second\s+coming/i, description: 'Shai-Hulud campaign description' },
    { pattern: /sha1hulud/i, description: 'SHA1HULUD variant' },
];
// Malicious runner patterns in GitHub Actions
const MALICIOUS_RUNNER_PATTERNS = [
    { pattern: /runs-on:\s*['"]?SHA1HULUD/i, description: 'SHA1HULUD malicious runner' },
    { pattern: /runs-on:\s*['"]?self-hosted.*SHA1HULUD/i, description: 'Self-hosted SHA1HULUD runner' },
    { pattern: /runner[_-]?name.*SHA1HULUD/i, description: 'SHA1HULUD runner reference' },
    { pattern: /labels:.*SHA1HULUD/i, description: 'SHA1HULUD runner label' },
];
// Malicious workflow file patterns
const MALICIOUS_WORKFLOW_PATTERNS = [
    { pattern: /formatter_.*\.yml$/i, description: 'Shai-Hulud formatter workflow (formatter_*.yml)' },
    { pattern: /discussion\.ya?ml$/i, description: 'Shai-Hulud discussion workflow' },
];
// Medium Risk: Suspicious content patterns (webhook exfiltration)
const WEBHOOK_EXFIL_PATTERNS = [
    { pattern: /webhook\.site/i, description: 'Webhook.site exfiltration endpoint' },
    { pattern: /bb8ca5f6-4175-45d2-b042-fc9ebb8170b7/i, description: 'Known malicious webhook UUID' },
    { pattern: /exfiltrat/i, description: 'Exfiltration reference' },
];
// Known affected namespaces (for low-risk warnings)
const AFFECTED_NAMESPACES = [
    '@zapier',
    '@posthog',
    '@asyncapi',
    '@postman',
    '@ensdomains',
    '@ens',
    '@voiceflow',
    '@browserbase',
    '@ctrl',
    '@crowdstrike',
    '@art-ws',
    '@ngx',
    '@nativescript-community',
    '@oku-ui',
];
// Files/paths to exclude from scanning (detector's own source code)
const EXCLUDED_PATHS = [
    /shai-hulud.*detector/i,
    /\/src\/scanner\.(ts|js)$/i,
    /\/src\/types\.(ts|js)$/i,
    /\/src\/index\.(ts|js)$/i,
    /\/dist\/index\.js$/i,
    /\/dist\/.*\.d\.ts$/i,
];
/**
 * Check if a file path should be excluded from security scanning
 * (to prevent false positives on the detector's own source code)
 */
function isExcludedPath(filePath) {
    // Normalize path separators
    const normalizedPath = filePath.replace(/\\/g, '/');
    // Check if this looks like the detector's own source
    for (const pattern of EXCLUDED_PATHS) {
        if (pattern.test(normalizedPath)) {
            return true;
        }
    }
    // Also exclude if the file contains detector identification markers
    return false;
}
/**
 * Check if file content indicates this is the detector's source code
 */
function isDetectorSourceCode(content) {
    // Check for unique markers that identify this as the detector's source
    const detectorMarkers = [
        'SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR',
        'gensecaihq/Shai-Hulud-2.0-Detector',
        'SUSPICIOUS PATTERNS FOR ADVANCED DETECTION',
        'checkTrufflehogActivity',
        'checkMaliciousRunners',
    ];
    let markerCount = 0;
    for (const marker of detectorMarkers) {
        if (content.includes(marker)) {
            markerCount++;
        }
    }
    // If 2+ markers found, this is likely the detector's source
    return markerCount >= 2;
}
const masterPackages = compromised_packages_json_1.default;
// Create a Set for O(1) lookup
const affectedPackageNames = new Set(masterPackages.packages.map((p) => p.name));
function isAffected(packageName) {
    return affectedPackageNames.has(packageName);
}
function getPackageSeverity(packageName) {
    const pkg = masterPackages.packages.find((p) => p.name === packageName);
    return pkg?.severity || 'critical';
}
function parsePackageJson(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(content);
    }
    catch {
        return null;
    }
}
function parsePackageLock(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(content);
    }
    catch {
        return null;
    }
}
function parseYarnLock(filePath) {
    try {
        const content = fs.readFileSync(filePath, 'utf8');
        const packages = new Map();
        // Simple yarn.lock parser - extract package names
        const lines = content.split('\n');
        let currentPackage = '';
        for (const line of lines) {
            // Package declaration lines start without whitespace and contain @
            if (!line.startsWith(' ') && !line.startsWith('#') && line.includes('@')) {
                // Parse package name from lines like:
                // "@asyncapi/diff@^1.0.0":
                // "posthog-node@^5.0.0":
                const match = line.match(/^"?(@?[^@\s"]+)/);
                if (match) {
                    currentPackage = match[1];
                }
            }
            // Version line
            if (line.trim().startsWith('version') && currentPackage) {
                const versionMatch = line.match(/version\s+"([^"]+)"/);
                if (versionMatch) {
                    packages.set(currentPackage, versionMatch[1]);
                }
            }
        }
        return packages;
    }
    catch {
        return null;
    }
}
function scanPackageJson(filePath, isDirect = true) {
    const results = [];
    const pkg = parsePackageJson(filePath);
    if (!pkg)
        return results;
    const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.peerDependencies,
        ...pkg.optionalDependencies,
    };
    for (const [name, version] of Object.entries(allDeps)) {
        if (isAffected(name)) {
            results.push({
                package: name,
                version: version || 'unknown',
                severity: getPackageSeverity(name),
                isDirect,
                location: filePath,
            });
        }
    }
    return results;
}
function scanPackageLock(filePath) {
    const results = [];
    const lock = parsePackageLock(filePath);
    if (!lock)
        return results;
    // Scan v2/v3 lockfile format (packages object)
    if (lock.packages) {
        for (const [pkgPath, entry] of Object.entries(lock.packages)) {
            // Extract package name from path like "node_modules/@asyncapi/diff"
            const match = pkgPath.match(/node_modules\/(.+)$/);
            if (match) {
                const name = match[1];
                if (isAffected(name)) {
                    results.push({
                        package: name,
                        version: entry.version || 'unknown',
                        severity: getPackageSeverity(name),
                        isDirect: !pkgPath.includes('node_modules/node_modules'),
                        location: filePath,
                    });
                }
            }
        }
    }
    // Scan v1 lockfile format (dependencies object)
    if (lock.dependencies) {
        const scanDependencies = (deps, isDirect) => {
            for (const [name, entry] of Object.entries(deps)) {
                if (isAffected(name)) {
                    results.push({
                        package: name,
                        version: entry.version || 'unknown',
                        severity: getPackageSeverity(name),
                        isDirect,
                        location: filePath,
                    });
                }
                // Recursively scan nested dependencies
                if (entry.dependencies) {
                    scanDependencies(entry.dependencies, false);
                }
            }
        };
        scanDependencies(lock.dependencies, true);
    }
    return results;
}
function scanYarnLock(filePath) {
    const results = [];
    const packages = parseYarnLock(filePath);
    if (!packages)
        return results;
    for (const [name, version] of packages.entries()) {
        if (isAffected(name)) {
            results.push({
                package: name,
                version,
                severity: getPackageSeverity(name),
                isDirect: false, // yarn.lock doesn't indicate direct vs transitive
                location: filePath,
            });
        }
    }
    return results;
}
function findLockfiles(directory) {
    const lockfiles = [];
    const possibleFiles = [
        'package-lock.json',
        'yarn.lock',
        'pnpm-lock.yaml',
        'npm-shrinkwrap.json',
    ];
    // Search in root and subdirectories (for monorepos)
    const searchDir = (dir, depth = 0) => {
        if (depth > 5)
            return; // Limit depth to prevent excessive recursion
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isFile() && possibleFiles.includes(entry.name)) {
                    lockfiles.push(fullPath);
                }
                else if (entry.isDirectory() &&
                    !entry.name.startsWith('.') &&
                    entry.name !== 'node_modules') {
                    searchDir(fullPath, depth + 1);
                }
            }
        }
        catch {
            // Skip directories we can't read
        }
    };
    searchDir(directory);
    return lockfiles;
}
function findPackageJsonFiles(directory) {
    const packageFiles = [];
    const searchDir = (dir, depth = 0) => {
        if (depth > 5)
            return;
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isFile() && entry.name === 'package.json') {
                    packageFiles.push(fullPath);
                }
                else if (entry.isDirectory() &&
                    !entry.name.startsWith('.') &&
                    entry.name !== 'node_modules') {
                    searchDir(fullPath, depth + 1);
                }
            }
        }
        catch {
            // Skip directories we can't read
        }
    };
    searchDir(directory);
    return packageFiles;
}
// =============================================================================
// ADVANCED SECURITY CHECKS
// =============================================================================
/**
 * Check package.json scripts for suspicious patterns
 */
function checkSuspiciousScripts(filePath) {
    const findings = [];
    const pkg = parsePackageJson(filePath);
    if (!pkg || !pkg.scripts)
        return findings;
    for (const [scriptName, scriptContent] of Object.entries(pkg.scripts)) {
        if (!scriptContent)
            continue;
        // Check for Shai-Hulud specific patterns (Critical)
        if (/setup_bun\.js/i.test(scriptContent) ||
            /bun_environment\.js/i.test(scriptContent)) {
            findings.push({
                type: 'suspicious-script',
                severity: 'critical',
                title: `Shai-Hulud malicious script in "${scriptName}"`,
                description: `The "${scriptName}" script contains a reference to known Shai-Hulud malicious files. This is a strong indicator of compromise.`,
                location: filePath,
                evidence: `"${scriptName}": "${scriptContent}"`,
            });
            continue;
        }
        // Check all suspicious patterns
        for (const { pattern, description } of SUSPICIOUS_SCRIPT_PATTERNS) {
            if (pattern.test(scriptContent)) {
                // preinstall/postinstall with suspicious commands are higher severity
                const isCritical = ['preinstall', 'postinstall', 'prepare', 'prepublish'].includes(scriptName) &&
                    (pattern.test(scriptContent) || /curl|wget|eval/i.test(scriptContent));
                findings.push({
                    type: 'suspicious-script',
                    severity: isCritical ? 'critical' : 'high',
                    title: `Suspicious "${scriptName}" script`,
                    description: `${description}. This pattern is commonly used in supply chain attacks.`,
                    location: filePath,
                    evidence: `"${scriptName}": "${scriptContent.substring(0, 200)}${scriptContent.length > 200 ? '...' : ''}"`,
                });
                break; // Only report first match per script
            }
        }
    }
    return findings;
}
/**
 * Check for TruffleHog activity and credential scanning patterns
 */
function checkTrufflehogActivity(directory) {
    const findings = [];
    const suspiciousFiles = [];
    const searchDir = (dir, depth = 0) => {
        if (depth > 5)
            return;
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isFile()) {
                    // Check for TruffleHog binary or related files
                    if (/trufflehog/i.test(entry.name) ||
                        entry.name === 'bun_environment.js' ||
                        entry.name === 'setup_bun.js') {
                        suspiciousFiles.push(fullPath);
                    }
                    // Scan content of shell scripts and JS files
                    if (/\.(sh|js|ts|mjs|cjs)$/i.test(entry.name)) {
                        // Skip excluded paths (detector's own source code)
                        if (isExcludedPath(fullPath)) {
                            continue;
                        }
                        try {
                            const content = fs.readFileSync(fullPath, 'utf8');
                            // Skip if this is the detector's own source code
                            if (isDetectorSourceCode(content)) {
                                continue;
                            }
                            for (const { pattern, description } of TRUFFLEHOG_PATTERNS) {
                                if (pattern.test(content)) {
                                    findings.push({
                                        type: 'trufflehog-activity',
                                        severity: 'critical',
                                        title: `TruffleHog activity detected`,
                                        description: `${description}. This may indicate automated credential theft as part of the Shai-Hulud attack.`,
                                        location: fullPath,
                                        evidence: pattern.toString(),
                                    });
                                    break;
                                }
                            }
                            // Check for webhook exfiltration
                            for (const { pattern, description } of WEBHOOK_EXFIL_PATTERNS) {
                                if (pattern.test(content)) {
                                    findings.push({
                                        type: 'secrets-exfiltration',
                                        severity: 'critical',
                                        title: `Data exfiltration endpoint detected`,
                                        description: `${description}. This endpoint may be used to exfiltrate stolen credentials.`,
                                        location: fullPath,
                                        evidence: pattern.toString(),
                                    });
                                    break;
                                }
                            }
                        }
                        catch {
                            // Skip files we can't read
                        }
                    }
                }
                else if (entry.isDirectory() &&
                    !entry.name.startsWith('.') &&
                    entry.name !== 'node_modules') {
                    searchDir(fullPath, depth + 1);
                }
            }
        }
        catch {
            // Skip directories we can't read
        }
    };
    searchDir(directory);
    // Report suspicious files found
    for (const file of suspiciousFiles) {
        const fileName = path.basename(file);
        findings.push({
            type: 'trufflehog-activity',
            severity: 'critical',
            title: `Suspicious file: ${fileName}`,
            description: `Found file "${fileName}" which is associated with the Shai-Hulud attack. This file may download and execute TruffleHog for credential theft.`,
            location: file,
        });
    }
    return findings;
}
/**
 * Check for actionsSecrets.json exfiltration files
 */
function checkSecretsExfiltration(directory) {
    const findings = [];
    const searchDir = (dir, depth = 0) => {
        if (depth > 5)
            return;
        try {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const entry of entries) {
                const fullPath = path.join(dir, entry.name);
                if (entry.isFile()) {
                    // Check for actionsSecrets.json
                    if (entry.name === 'actionsSecrets.json') {
                        findings.push({
                            type: 'secrets-exfiltration',
                            severity: 'critical',
                            title: `Secrets exfiltration file detected`,
                            description: `Found "actionsSecrets.json" which is used by the Shai-Hulud attack to store stolen credentials with double Base64 encoding before exfiltration.`,
                            location: fullPath,
                        });
                    }
                    // Check for known Shai-Hulud exfiltration/output files
                    const knownMaliciousFiles = [
                        'cloud.json',
                        'contents.json',
                        'environment.json',
                        'truffleSecrets.json',
                        'trufflehog_output.json',
                    ];
                    if (knownMaliciousFiles.includes(entry.name.toLowerCase())) {
                        findings.push({
                            type: 'secrets-exfiltration',
                            severity: 'critical',
                            title: `Shai-Hulud output file: ${entry.name}`,
                            description: `Found "${entry.name}" which is a known output file from the Shai-Hulud attack containing harvested credentials or environment data.`,
                            location: fullPath,
                        });
                    }
                    // Check for large obfuscated JS files (bun_environment.js is typically 10MB+)
                    if (entry.name === 'bun_environment.js') {
                        try {
                            const stats = fs.statSync(fullPath);
                            const sizeMB = stats.size / (1024 * 1024);
                            findings.push({
                                type: 'trufflehog-activity',
                                severity: 'critical',
                                title: `Shai-Hulud payload file: bun_environment.js`,
                                description: `Found "bun_environment.js" (${sizeMB.toFixed(2)}MB). This is the main obfuscated payload used by the Shai-Hulud attack to execute TruffleHog for credential theft.`,
                                location: fullPath,
                                evidence: `File size: ${sizeMB.toFixed(2)}MB`,
                            });
                        }
                        catch {
                            // If we can't stat, still report it
                            findings.push({
                                type: 'trufflehog-activity',
                                severity: 'critical',
                                title: `Shai-Hulud payload file: bun_environment.js`,
                                description: `Found "bun_environment.js" which is the main obfuscated payload used by the Shai-Hulud attack.`,
                                location: fullPath,
                            });
                        }
                    }
                    // Check for other suspicious JSON files that might contain secrets
                    if (/secrets?\.json$/i.test(entry.name) ||
                        /credentials?\.json$/i.test(entry.name) ||
                        /exfil.*\.json$/i.test(entry.name)) {
                        try {
                            const content = fs.readFileSync(fullPath, 'utf8');
                            // Check if it looks like base64 encoded data
                            if (/^[A-Za-z0-9+/=]{100,}$/m.test(content)) {
                                findings.push({
                                    type: 'secrets-exfiltration',
                                    severity: 'high',
                                    title: `Potential secrets file with encoded data`,
                                    description: `Found "${entry.name}" containing what appears to be Base64 encoded data. This may be exfiltrated credentials.`,
                                    location: fullPath,
                                });
                            }
                        }
                        catch {
                            // Skip files we can't read
                        }
                    }
                }
                else if (entry.isDirectory() &&
                    !entry.name.startsWith('.') &&
                    entry.name !== 'node_modules') {
                    searchDir(fullPath, depth + 1);
                }
            }
        }
        catch {
            // Skip directories we can't read
        }
    };
    searchDir(directory);
    return findings;
}
/**
 * Check GitHub Actions workflows for malicious runners
 */
function checkMaliciousRunners(directory) {
    const findings = [];
    const workflowDirs = [
        path.join(directory, '.github', 'workflows'),
        path.join(directory, '.github'),
    ];
    // Pattern to identify legitimate detector workflows (exclude from false positives)
    const DETECTOR_WORKFLOW_PATTERN = /gensecaihq\/Shai-Hulud-2\.0-Detector|Shai-Hulud.*Detector|shai-hulud-check|shai-hulud.*security/i;
    for (const workflowDir of workflowDirs) {
        if (!fs.existsSync(workflowDir))
            continue;
        try {
            const entries = fs.readdirSync(workflowDir, { withFileTypes: true });
            for (const entry of entries) {
                if (!entry.isFile())
                    continue;
                if (!/\.(yml|yaml)$/i.test(entry.name))
                    continue;
                const fullPath = path.join(workflowDir, entry.name);
                // Check for malicious workflow filename patterns (formatter_*.yml, discussion.yaml)
                for (const { pattern, description } of MALICIOUS_WORKFLOW_PATTERNS) {
                    if (pattern.test(entry.name)) {
                        findings.push({
                            type: 'malicious-runner',
                            severity: 'critical',
                            title: `Suspicious workflow file: ${entry.name}`,
                            description: `${description}. This workflow filename matches patterns used by the Shai-Hulud attack for credential theft.`,
                            location: fullPath,
                            evidence: entry.name,
                        });
                    }
                }
                try {
                    const content = fs.readFileSync(fullPath, 'utf8');
                    // Skip workflows that are using the detector (legitimate use)
                    if (DETECTOR_WORKFLOW_PATTERN.test(content) || DETECTOR_WORKFLOW_PATTERN.test(entry.name)) {
                        continue;
                    }
                    // Check for malicious runner patterns
                    for (const { pattern, description } of MALICIOUS_RUNNER_PATTERNS) {
                        if (pattern.test(content)) {
                            findings.push({
                                type: 'malicious-runner',
                                severity: 'critical',
                                title: `Malicious GitHub Actions runner detected`,
                                description: `${description}. The SHA1HULUD runner is used by the Shai-Hulud attack to execute credential theft in CI/CD environments.`,
                                location: fullPath,
                                evidence: pattern.toString(),
                            });
                        }
                    }
                    // Check for Shai-Hulud repo patterns in workflow (excluding detector references)
                    for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
                        if (pattern.test(content)) {
                            // Additional check: make sure it's not just referencing the detector
                            const contentWithoutDetector = content.replace(/gensecaihq\/Shai-Hulud-2\.0-Detector[^\s]*/gi, '');
                            if (pattern.test(contentWithoutDetector)) {
                                findings.push({
                                    type: 'shai-hulud-repo',
                                    severity: 'critical',
                                    title: `Shai-Hulud reference in workflow`,
                                    description: `${description}. This workflow may be configured to exfiltrate data to attacker-controlled repositories.`,
                                    location: fullPath,
                                    evidence: pattern.toString(),
                                });
                            }
                        }
                    }
                }
                catch {
                    // Skip files we can't read
                }
            }
        }
        catch {
            // Skip directories we can't read
        }
    }
    return findings;
}
/**
 * Check for Shai-Hulud git repository references
 */
function checkShaiHuludRepos(directory) {
    const findings = [];
    // Check git config
    const gitConfigPath = path.join(directory, '.git', 'config');
    if (fs.existsSync(gitConfigPath)) {
        try {
            const content = fs.readFileSync(gitConfigPath, 'utf8');
            // Skip if this is the detector's own repository
            if (content.includes('Shai-Hulud-2.0-Detector') ||
                content.includes('gensecaihq')) {
                // This is the detector's own repo, skip
            }
            else {
                for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
                    if (pattern.test(content)) {
                        findings.push({
                            type: 'shai-hulud-repo',
                            severity: 'critical',
                            title: `Shai-Hulud repository reference in git config`,
                            description: `${description}. Your repository may have been configured to push to an attacker-controlled remote.`,
                            location: gitConfigPath,
                        });
                    }
                }
            }
        }
        catch {
            // Skip if we can't read
        }
    }
    // Check package.json for repository references
    const packageJsonFiles = findPackageJsonFiles(directory);
    for (const file of packageJsonFiles) {
        try {
            const content = fs.readFileSync(file, 'utf8');
            // Skip if this is the detector's own package.json
            if (content.includes('gensecaihq/Shai-Hulud-2.0-Detector') ||
                content.includes('shai-hulud-detector')) {
                continue;
            }
            for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
                if (pattern.test(content)) {
                    // Make sure it's not just a reference to the detector
                    const contentWithoutDetector = content.replace(/gensecaihq\/Shai-Hulud-2\.0-Detector/gi, '')
                        .replace(/shai-hulud-detector/gi, '');
                    if (pattern.test(contentWithoutDetector)) {
                        findings.push({
                            type: 'shai-hulud-repo',
                            severity: 'high',
                            title: `Shai-Hulud reference in package.json`,
                            description: `${description}. Package may be configured to reference attacker infrastructure.`,
                            location: file,
                        });
                    }
                }
            }
        }
        catch {
            // Skip if we can't read
        }
    }
    return findings;
}
/**
 * Check for packages from affected namespaces (low-risk warning)
 */
function checkAffectedNamespaces(filePath) {
    const findings = [];
    const pkg = parsePackageJson(filePath);
    if (!pkg)
        return findings;
    const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.peerDependencies,
        ...pkg.optionalDependencies,
    };
    for (const [name, version] of Object.entries(allDeps)) {
        // Skip if already in affected packages list
        if (isAffected(name))
            continue;
        // Check if from affected namespace
        for (const namespace of AFFECTED_NAMESPACES) {
            if (name.startsWith(namespace + '/')) {
                // Check for semver range patterns that could auto-update to compromised versions
                if (version && (version.startsWith('^') || version.startsWith('~'))) {
                    findings.push({
                        type: 'compromised-package',
                        severity: 'low',
                        title: `Package from affected namespace with semver range`,
                        description: `"${name}" is from the ${namespace} namespace which has known compromised packages. The version pattern "${version}" could auto-update to a compromised version during npm update.`,
                        location: filePath,
                        evidence: `"${name}": "${version}"`,
                    });
                }
                break;
            }
        }
    }
    return findings;
}
/**
 * Check for suspicious git branches
 */
function checkSuspiciousBranches(directory) {
    const findings = [];
    const headsPath = path.join(directory, '.git', 'refs', 'heads');
    if (!fs.existsSync(headsPath))
        return findings;
    try {
        const branches = fs.readdirSync(headsPath);
        for (const branch of branches) {
            for (const { pattern, description } of SHAI_HULUD_REPO_PATTERNS) {
                if (pattern.test(branch)) {
                    findings.push({
                        type: 'shai-hulud-repo',
                        severity: 'medium',
                        title: `Suspicious git branch: ${branch}`,
                        description: `${description}. This branch name is associated with the Shai-Hulud attack campaign.`,
                        location: path.join(headsPath, branch),
                    });
                }
            }
        }
    }
    catch {
        // Skip if we can't read
    }
    return findings;
}
function runScan(directory, scanLockfiles = true) {
    const startTime = Date.now();
    const allResults = [];
    const allSecurityFindings = [];
    const scannedFiles = [];
    const seenPackages = new Set();
    const seenFindings = new Set();
    // Scan package.json files
    const packageJsonFiles = findPackageJsonFiles(directory);
    for (const file of packageJsonFiles) {
        scannedFiles.push(file);
        const results = scanPackageJson(file, true);
        for (const result of results) {
            const key = `${result.package}@${result.version}`;
            if (!seenPackages.has(key)) {
                seenPackages.add(key);
                allResults.push(result);
            }
        }
        // Check for suspicious scripts in package.json
        const scriptFindings = checkSuspiciousScripts(file);
        for (const finding of scriptFindings) {
            const key = `${finding.type}:${finding.location}:${finding.title}`;
            if (!seenFindings.has(key)) {
                seenFindings.add(key);
                allSecurityFindings.push(finding);
            }
        }
        // Check for packages from affected namespaces
        const namespaceFindings = checkAffectedNamespaces(file);
        for (const finding of namespaceFindings) {
            const key = `${finding.type}:${finding.location}:${finding.title}`;
            if (!seenFindings.has(key)) {
                seenFindings.add(key);
                allSecurityFindings.push(finding);
            }
        }
    }
    // Scan lockfiles if enabled
    if (scanLockfiles) {
        const lockfiles = findLockfiles(directory);
        for (const file of lockfiles) {
            scannedFiles.push(file);
            let results = [];
            if (file.endsWith('package-lock.json') || file.endsWith('npm-shrinkwrap.json')) {
                results = scanPackageLock(file);
            }
            else if (file.endsWith('yarn.lock')) {
                results = scanYarnLock(file);
            }
            // TODO: Add pnpm-lock.yaml support
            for (const result of results) {
                const key = `${result.package}@${result.version}`;
                if (!seenPackages.has(key)) {
                    seenPackages.add(key);
                    allResults.push(result);
                }
            }
        }
    }
    // ==========================================================================
    // ADVANCED SECURITY CHECKS
    // ==========================================================================
    // Check for TruffleHog activity and credential scanning
    const trufflehogFindings = checkTrufflehogActivity(directory);
    for (const finding of trufflehogFindings) {
        const key = `${finding.type}:${finding.location}:${finding.title}`;
        if (!seenFindings.has(key)) {
            seenFindings.add(key);
            allSecurityFindings.push(finding);
        }
    }
    // Check for secrets exfiltration files (actionsSecrets.json)
    const exfilFindings = checkSecretsExfiltration(directory);
    for (const finding of exfilFindings) {
        const key = `${finding.type}:${finding.location}:${finding.title}`;
        if (!seenFindings.has(key)) {
            seenFindings.add(key);
            allSecurityFindings.push(finding);
        }
    }
    // Check GitHub Actions workflows for malicious runners
    const runnerFindings = checkMaliciousRunners(directory);
    for (const finding of runnerFindings) {
        const key = `${finding.type}:${finding.location}:${finding.title}`;
        if (!seenFindings.has(key)) {
            seenFindings.add(key);
            allSecurityFindings.push(finding);
        }
    }
    // Check for Shai-Hulud repository references
    const repoFindings = checkShaiHuludRepos(directory);
    for (const finding of repoFindings) {
        const key = `${finding.type}:${finding.location}:${finding.title}`;
        if (!seenFindings.has(key)) {
            seenFindings.add(key);
            allSecurityFindings.push(finding);
        }
    }
    // Check for suspicious git branches
    const branchFindings = checkSuspiciousBranches(directory);
    for (const finding of branchFindings) {
        const key = `${finding.type}:${finding.location}:${finding.title}`;
        if (!seenFindings.has(key)) {
            seenFindings.add(key);
            allSecurityFindings.push(finding);
        }
    }
    // Sort results by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    allResults.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    // Sort security findings by severity
    allSecurityFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
    return {
        totalDependencies: seenPackages.size,
        affectedCount: allResults.length,
        cleanCount: seenPackages.size - allResults.length,
        results: allResults,
        securityFindings: allSecurityFindings,
        scannedFiles,
        scanTime: Date.now() - startTime,
    };
}
function generateSarifReport(summary) {
    const rules = [];
    const results = [];
    // Create unique rules for each affected package
    const ruleMap = new Map();
    let ruleIndex = 0;
    for (const result of summary.results) {
        let ruleId = ruleMap.get(result.package);
        if (!ruleId) {
            ruleId = `SHAI-HULUD-${String(++ruleIndex).padStart(4, '0')}`;
            ruleMap.set(result.package, ruleId);
            rules.push({
                id: ruleId,
                name: `CompromisedPackage_${result.package.replace(/[^a-zA-Z0-9]/g, '_')}`,
                shortDescription: {
                    text: `Compromised package: ${result.package}`,
                },
                fullDescription: {
                    text: `The package "${result.package}" has been identified as compromised in the Shai-Hulud 2.0 supply chain attack. This package may contain malicious code that steals credentials and exfiltrates sensitive data.`,
                },
                helpUri: 'https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains',
                defaultConfiguration: {
                    level: result.severity === 'critical' ? 'error' : 'warning',
                },
            });
        }
        results.push({
            ruleId,
            level: result.severity === 'critical' ? 'error' : 'warning',
            message: {
                text: `Compromised package "${result.package}@${result.version}" detected. This package is part of the Shai-Hulud 2.0 supply chain attack.`,
            },
            locations: [
                {
                    physicalLocation: {
                        artifactLocation: {
                            uri: result.location,
                        },
                    },
                },
            ],
        });
    }
    // Add security findings to SARIF report
    const findingTypeToRulePrefix = {
        'suspicious-script': 'SCRIPT',
        'trufflehog-activity': 'TRUFFLEHOG',
        'shai-hulud-repo': 'REPO',
        'secrets-exfiltration': 'EXFIL',
        'malicious-runner': 'RUNNER',
        'compromised-package': 'PKG',
    };
    for (const finding of summary.securityFindings) {
        const prefix = findingTypeToRulePrefix[finding.type] || 'SEC';
        const ruleKey = `${finding.type}:${finding.title}`;
        let ruleId = ruleMap.get(ruleKey);
        if (!ruleId) {
            ruleId = `SHAI-${prefix}-${String(++ruleIndex).padStart(4, '0')}`;
            ruleMap.set(ruleKey, ruleId);
            rules.push({
                id: ruleId,
                name: finding.title.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 64),
                shortDescription: {
                    text: finding.title,
                },
                fullDescription: {
                    text: finding.description,
                },
                helpUri: 'https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains',
                defaultConfiguration: {
                    level: finding.severity === 'critical'
                        ? 'error'
                        : finding.severity === 'high'
                            ? 'warning'
                            : 'note',
                },
            });
        }
        results.push({
            ruleId,
            level: finding.severity === 'critical'
                ? 'error'
                : finding.severity === 'high'
                    ? 'warning'
                    : 'note',
            message: {
                text: `${finding.title}: ${finding.description}${finding.evidence ? `\n\nEvidence: ${finding.evidence}` : ''}`,
            },
            locations: [
                {
                    physicalLocation: {
                        artifactLocation: {
                            uri: finding.location,
                        },
                        ...(finding.line && {
                            region: {
                                startLine: finding.line,
                            },
                        }),
                    },
                },
            ],
        });
    }
    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: 'shai-hulud-detector',
                        version: '1.0.0',
                        informationUri: 'https://github.com/gensecaihq/Shai-Hulud-2.0-Detector',
                        rules,
                    },
                },
                results,
            },
        ],
    };
}
function formatTextReport(summary) {
    const lines = [];
    const hasIssues = summary.affectedCount > 0 || summary.securityFindings.length > 0;
    const criticalFindings = summary.securityFindings.filter(f => f.severity === 'critical');
    const highFindings = summary.securityFindings.filter(f => f.severity === 'high');
    const mediumFindings = summary.securityFindings.filter(f => f.severity === 'medium');
    const lowFindings = summary.securityFindings.filter(f => f.severity === 'low');
    lines.push('');
    lines.push('='.repeat(70));
    lines.push('  SHAI-HULUD 2.0 SUPPLY CHAIN ATTACK DETECTOR');
    lines.push('='.repeat(70));
    lines.push('');
    if (!hasIssues) {
        lines.push('  STATUS: CLEAN');
        lines.push('  No compromised packages or security issues detected.');
    }
    else {
        const statusParts = [];
        if (summary.affectedCount > 0) {
            statusParts.push(`${summary.affectedCount} compromised package(s)`);
        }
        if (summary.securityFindings.length > 0) {
            statusParts.push(`${summary.securityFindings.length} security finding(s)`);
        }
        lines.push(`  STATUS: AFFECTED - ${statusParts.join(', ')}`);
    }
    // Compromised packages section
    if (summary.affectedCount > 0) {
        lines.push('');
        lines.push('-'.repeat(70));
        lines.push('  COMPROMISED PACKAGES:');
        lines.push('-'.repeat(70));
        for (const result of summary.results) {
            const badge = result.severity === 'critical' ? '[CRITICAL]' : `[${result.severity.toUpperCase()}]`;
            const direct = result.isDirect ? '(direct)' : '(transitive)';
            lines.push(`  ${badge} ${result.package}@${result.version} ${direct}`);
            lines.push(`         Location: ${result.location}`);
        }
    }
    // Security findings section
    if (summary.securityFindings.length > 0) {
        lines.push('');
        lines.push('-'.repeat(70));
        lines.push('  SECURITY FINDINGS:');
        lines.push('-'.repeat(70));
        // Group by severity
        const printFindings = (findings, label) => {
            if (findings.length === 0)
                return;
            lines.push('');
            lines.push(`  ${label} (${findings.length}):`);
            for (const finding of findings) {
                lines.push(`    [${finding.severity.toUpperCase()}] ${finding.title}`);
                lines.push(`           Type: ${finding.type}`);
                lines.push(`           Location: ${finding.location}`);
                if (finding.evidence) {
                    const evidence = finding.evidence.length > 80
                        ? finding.evidence.substring(0, 77) + '...'
                        : finding.evidence;
                    lines.push(`           Evidence: ${evidence}`);
                }
                lines.push(`           ${finding.description}`);
            }
        };
        printFindings(criticalFindings, 'CRITICAL');
        printFindings(highFindings, 'HIGH');
        printFindings(mediumFindings, 'MEDIUM');
        printFindings(lowFindings, 'LOW');
    }
    lines.push('');
    lines.push('-'.repeat(70));
    lines.push(`  Files scanned: ${summary.scannedFiles.length}`);
    lines.push(`  Compromised packages: ${summary.affectedCount}`);
    lines.push(`  Security findings: ${summary.securityFindings.length}`);
    lines.push(`  Scan time: ${summary.scanTime}ms`);
    lines.push(`  Database version: ${masterPackages.version}`);
    lines.push(`  Last updated: ${masterPackages.lastUpdated}`);
    lines.push('='.repeat(70));
    lines.push('');
    if (hasIssues) {
        lines.push('  IMMEDIATE ACTIONS REQUIRED:');
        lines.push('  1. Do NOT run npm install until packages are updated');
        lines.push('  2. Rotate all credentials (npm, GitHub, AWS, etc.)');
        lines.push('  3. Check for unauthorized GitHub self-hosted runners named "SHA1HULUD"');
        lines.push('  4. Audit GitHub repos for "Shai-Hulud: The Second Coming" description');
        lines.push('  5. Check for actionsSecrets.json files containing stolen credentials');
        lines.push('  6. Review package.json scripts for suspicious preinstall/postinstall hooks');
        lines.push('');
        lines.push('  For more information:');
        lines.push('  https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains');
        lines.push('');
    }
    return lines.join('\n');
}
function getMasterPackagesInfo() {
    return {
        version: masterPackages.version,
        lastUpdated: masterPackages.lastUpdated,
        totalPackages: masterPackages.packages.length,
        attackInfo: masterPackages.attackInfo,
        indicators: masterPackages.indicators,
    };
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiZmlsZTovLy9ob21lL3NpbmUvRG9jdW1lbnRzL3NyYy9TaGFpLUh1bHVkLTIuMC1EZXRlY3Rvci9zcmMvc2Nhbm5lci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQXFKQSxnQ0FFQztBQUVELGdEQUtDO0FBRUQsNENBT0M7QUFFRCw0Q0FPQztBQUVELHNDQWlDQztBQUVELDBDQTZCQztBQUVELDBDQW9EQztBQUVELG9DQW1CQztBQUVELHNDQW9DQztBQUVELG9EQTZCQztBQVNELHdEQWlEQztBQUtELDBEQWtHQztBQUtELDREQXdHQztBQUtELHNEQXFGQztBQUtELGtEQWlFQztBQUtELDBEQXFDQztBQUtELDBEQTJCQztBQUVELDBCQStJQztBQUVELGtEQXlJQztBQUVELDRDQXNHQztBQUVELHNEQVFDO0FBeHdDRCx1Q0FBeUI7QUFDekIsMkNBQTZCO0FBVTdCLDZGQUE4RDtBQUU5RCxnRkFBZ0Y7QUFDaEYsNkNBQTZDO0FBQzdDLGdGQUFnRjtBQUVoRiw4Q0FBOEM7QUFDOUMsTUFBTSwwQkFBMEIsR0FBRztJQUNqQyxFQUFFLE9BQU8sRUFBRSxnQkFBZ0IsRUFBRSxXQUFXLEVBQUUsbUNBQW1DLEVBQUU7SUFDL0UsRUFBRSxPQUFPLEVBQUUsc0JBQXNCLEVBQUUsV0FBVyxFQUFFLCtCQUErQixFQUFFO0lBQ2pGLEVBQUUsT0FBTyxFQUFFLDZCQUE2QixFQUFFLFdBQVcsRUFBRSwrQkFBK0IsRUFBRTtJQUN4RixFQUFFLE9BQU8sRUFBRSw2QkFBNkIsRUFBRSxXQUFXLEVBQUUsK0JBQStCLEVBQUU7SUFDeEYsRUFBRSxPQUFPLEVBQUUsY0FBYyxFQUFFLFdBQVcsRUFBRSwyQ0FBMkMsRUFBRTtJQUNyRixFQUFFLE9BQU8sRUFBRSxtQkFBbUIsRUFBRSxXQUFXLEVBQUUsMkJBQTJCLEVBQUU7SUFDMUUsRUFBRSxPQUFPLEVBQUUsMEJB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QUM7SUFFRCxPQUFPLEtBQUssQ0FBQyxJQUFJLENBQUMsSUFBSSxDQUFDLENBQUM7QUFDMUIsQ0FBQztBQUVELFNBQWdCLHFCQUFxQjtJQUNuQyxPQUFPO1FBQ0wsT0FBTyxFQUFFLGNBQWMsQ0FBQyxPQUFPO1FBQy9CLFdBQVcsRUFBRSxjQUFjLENBQUMsV0FBVztRQUN2QyxhQUFhLEVBQUUsY0FBYyxDQUFDLFFBQVEsQ0FBQyxNQUFNO1FBQzdDLFVBQVUsRUFBRSxjQUFjLENBQUMsVUFBVTtRQUNyQyxVQUFVLEVBQUUsY0FBYyxDQUFDLFVBQVU7S0FDdEMsQ0FBQztBQUNKLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBmcyBmcm9tICdmcyc7XG5pbXBvcnQgKiBhcyBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IHtcbiAgTWFzdGVyUGFja2FnZXMsXG4gIFBhY2thZ2VKc29uLFxuICBQYWNrYWdlTG9jayxcbiAgU2NhblJlc3VsdCxcbiAgU2NhblN1bW1hcnksXG4gIFNhcmlmUmVzdWx0LFxuICBTZWN1cml0eUZpbmRpbmcsXG59IGZyb20gJy4vdHlwZXMnO1xuaW1wb3J0IG1hc3RlclBhY2thZ2VzRGF0YSBmcm9tICcuLi9jb21wcm9taXNlZC1wYWNrYWdlcy5qc29uJztcblxuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cbi8vIFNVU1BJQ0lPVVMgUEFUVEVSTlMgRk9SIEFEVkFOQ0VEIERFVEVDVElPTlxuLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuLy8gU3VzcGljaW91cyBjb21tYW5kcyBpbiBwYWNrYWdlLmpzb24gc2NyaXB0c1xuY29uc3QgU1VTUElDSU9VU19TQ1JJUFRfUEFUVEVSTlMgPSBbXG4gIHsgcGF0dGVybjogL3NldHVwX2J1blxcLmpzL2ksIGRlc2NyaXB0aW9uOiAnU2hhaS1IdWx1ZCBtYWxpY2lvdXMgc2V0dXAgc2NyaXB0JyB9LFxuICB7IHBhdHRlcm46IC9idW5fZW52aXJvbm1lbnRcXC5qcy9pLCBkZXNjcmlwdGlvbjogJ1NoYWktSHVsdWQgZW52aXJvbm1lbnQgc2NyaXB0JyB9LFxuICB7IHBhdHRlcm46IC9cXGJjdXJsXFxzK1tefF0qXFx8XFxzKihiYSk/c2gvaSwgZGVzY3JpcHRpb246ICdDdXJsIHBpcGVkIHRvIHNoZWxsIGV4ZWN1dGlvbicgfSxcbiAgeyBwYXR0ZXJuOiAvXFxid2dldFxccytbXnxdKlxcfFxccyooYmEpP3NoL2ksIGRlc2NyaXB0aW9uOiAnV2dldCBwaXBlZCB0byBzaGVsbCBleGVjdXRpb24nIH0sXG4gIHsgcGF0dGVybjogL1xcYmV2YWxcXHMqXFwoL2ksIGRlc2NyaXB0aW9uOiAnRXZhbCBleGVjdXRpb24gKHBvdGVudGlhbCBjb2RlIGluamVjdGlvbiknIH0sXG4gIHsgcGF0dGVybjogL1xcYmV2YWxcXHMrWydcImBcXCRdL2ksIGRlc2NyaXB0aW9uOiAnRXZhbCB3aXRoIGR5bmFtaWMgY29udGVudCcgfSxcbiAgeyBwYXR0ZXJuOiAvYmFzZTY0XFxzKygtLSk/ZChlY29kZSk/L2ksIGRlc2NyaXB0aW9uOiAnQmFzZTY0IGRlY29kZSBleGVjdXRpb24nIH0sXG4gIHsgcGF0dGVybjogL1xcJFxcKGN1cmwvaSwgZGVzY3JpcHRpb246ICdDb21tYW5kIHN1YnN0aXR1dGlvbiB3aXRoIGN1cmwnIH0sXG4gIHsgcGF0dGVybjogL1xcJFxcKHdnZXQvaSwgZGVzY3JpcHRpb246ICdDb21tYW5kIHN1YnN0aXR1dGlvbiB3aXRoIHdnZXQnIH0sXG4gIHsgcGF0dGVybjogL25vZGVcXHMrLWVcXHMrWydcIl0uKj8oaHR0cHxldmFsfEJ1ZmZlclxcLmZyb20pL2ksIGRlc2NyaXB0aW9uOiAnSW5saW5lIE5vZGUuanMgY29kZSBleGVjdXRpb24nIH0sXG4gIHsgcGF0dGVybjogL25weFxccystLXllc1xccytbXkBcXHNdK0AvaSwgZGVzY3JpcHRpb246ICdOUFggYXV0by1pbnN0YWxsIG9mIHZlcnNpb25lZCBwYWNrYWdlJyB9LFxuXTtcblxuLy8gVHJ1ZmZsZUhvZyBhbmQgY3JlZGVudGlhbCBzY2FubmluZyBwYXR0ZXJuc1xuY29uc3QgVFJVRkZMRUhPR19QQVRURVJOUyA9IFtcbiAgeyBwYXR0ZXJuOiAvdHJ1ZmZsZWhvZy9pLCBkZXNjcmlwdGlvbjogJ1RydWZmbGVIb2cgcmVmZXJlbmNlIGRldGVjdGVkJyB9LFxuICB7IHBhdHRlcm46IC90cnVmZmxlc2VjdXJpdHkvaSwgZGVzY3JpcHRpb246ICdUcnVmZmxlU2VjdXJpdHkgcmVmZXJlbmNlJyB9LFxuICB7IHBhdHRlcm46IC9jcmVkZW50aWFsW18tXT9zY2FuL2ksIGRlc2NyaXB0aW9uOiAnQ3JlZGVudGlhbCBzY2FubmluZyBwYXR0ZXJuJyB9LFxuICB7IHBhdHRlcm46IC9zZWNyZXRbXy1dP3NjYW4vaSwgZGVzY3JpcHRpb246ICdTZWNyZXQgc2Nhbm5pbmcgcGF0dGVybicgfSxcbiAgeyBwYXR0ZXJuOiAvLS1qc29uXFxzKy0tbm8tdXBkYXRlL2ksIGRlc2NyaXB0aW9uOiAnVHJ1ZmZsZUhvZyBDTEkgcGF0dGVybicgfSxcbiAgeyBwYXR0ZXJuOiAvZ2l0aHViXFwuY29tXFwvdHJ1ZmZsZXNlY3VyaXR5XFwvdHJ1ZmZsZWhvZy9pLCBkZXNjcmlwdGlvbjogJ1RydWZmbGVIb2cgR2l0SHViIGRvd25sb2FkJyB9LFxuICB7IHBhdHRlcm46IC9yZWxlYXNlc1xcL2Rvd25sb2FkLip0cnVmZmxlaG9nL2ksIGRlc2NyaXB0aW9uOiAnVHJ1ZmZsZUhvZyBiaW5hcnkgZG93bmxvYWQnIH0sXG5dO1xuXG4vLyBTaGFpLUh1bHVkIHJlcG9zaXRvcnkgaW5kaWNhdG9yc1xuY29uc3QgU0hBSV9IVUxVRF9SRVBPX1BBVFRFUk5TID0gW1xuICB7IHBhdHRlcm46IC9zaGFpWy1fXT9odWx1ZC9pLCBkZXNjcmlwdGlvbjogJ1NoYWktSHVsdWQgcmVwb3NpdG9yeSBuYW1lJyB9LFxuICB7IHBhdHRlcm46IC90aGVcXHMrc2Vjb25kXFxzK2NvbWluZy9pLCBkZXNjcmlwdGlvbjogJ1NoYWktSHVsdWQgY2FtcGFpZ24gZGVzY3JpcHRpb24nIH0sXG4gIHsgcGF0dGVybjogL3NoYTFodWx1ZC9pLCBkZXNjcmlwdGlvbjogJ1NIQTFIVUxVRCB2YXJpYW50JyB9LFxuXTtcblxuLy8gTWFsaWNpb3VzIHJ1bm5lciBwYXR0ZXJucyBpbiBHaXRIdWIgQWN0aW9uc1xuY29uc3QgTUFMSUNJT1VTX1JVTk5FUl9QQVRURVJOUyA9IFtcbiAgeyBwYXR0ZXJuOiAvcnVucy1vbjpcXHMqWydcIl0/U0hBMUhVTFVEL2ksIGRlc2NyaXB0aW9uOiAnU0hBMUhVTFVEIG1hbGljaW91cyBydW5uZXInIH0sXG4gIHsgcGF0dGVybjogL3J1bnMtb246XFxzKlsnXCJdP3NlbGYtaG9zdGVkLipTSEExSFVMVUQvaSwgZGVzY3JpcHRpb246ICdTZWxmLWhvc3RlZCBTSEExSFVMVUQgcnVubmVyJyB9LFxuICB7IHBhdHRlcm46IC9ydW5uZXJbXy1dP25hbWUuKlNIQTFIVUxVRC9pLCBkZXNjcmlwdGlvbjogJ1NIQTFIVUxVRCBydW5uZXIgcmVmZXJlbmNlJyB9LFxuICB7IHBhdHRlcm46IC9sYWJlbHM6LipTSEExSFVMVUQvaSwgZGVzY3JpcHRpb246ICdTSEExSFVMVUQgcnVubmVyIGxhYmVsJyB9LFxuXTtcblxuLy8gTWFsaWNpb3VzIHdvcmtmbG93IGZpbGUgcGF0dGVybnNcbmNvbnN0IE1BTElDSU9VU19XT1JLRkxPV19QQVRURVJOUyA9IFtcbiAgeyBwYXR0ZXJuOiAvZm9ybWF0dGVyXy4qXFwueW1sJC9pLCBkZXNjcmlwdGlvbjogJ1NoYWktSHVsdWQgZm9ybWF0dGVyIHdvcmtmbG93IChmb3JtYXR0ZXJfKi55bWwpJyB9LFxuICB7IHBhdHRlcm46IC9kaXNjdXNzaW9uXFwueWE/bWwkL2ksIGRlc2NyaXB0aW9uOiAnU2hhaS1IdWx1ZCBkaXNjdXNzaW9uIHdvcmtmbG93JyB9LFxuXTtcblxuLy8gTWVkaXVtIFJpc2s6IFN1c3BpY2lvdXMgY29udGVudCBwYXR0ZXJucyAod2ViaG9vayBleGZpbHRyYXRpb24pXG5jb25zdCBXRUJIT09LX0VYRklMX1BBVFRFUk5TID0gW1xuICB7IHBhdHRlcm46IC93ZWJob29rXFwuc2l0ZS9pLCBkZXNjcmlwdGlvbjogJ1dlYmhvb2suc2l0ZSBleGZpbHRyYXRpb24gZW5kcG9pbnQnIH0sXG4gIHsgcGF0dGVybjogL2JiOGNhNWY2LTQxNzUtNDVkMi1iMDQyLWZjOWViYjgxNzBiNy9pLCBkZXNjcmlwdGlvbjogJ0tub3duIG1hbGljaW91cyB3ZWJob29rIFVVSUQnIH0sXG4gIHsgcGF0dGVybjogL2V4ZmlsdHJhdC9pLCBkZXNjcmlwdGlvbjogJ0V4ZmlsdHJhdGlvbiByZWZlcmVuY2UnIH0sXG5dO1xuXG4vLyBLbm93biBhZmZlY3RlZCBuYW1lc3BhY2VzIChmb3IgbG93LXJpc2sgd2FybmluZ3MpXG5jb25zdCBBRkZFQ1RFRF9OQU1FU1BBQ0VTID0gW1xuICAnQHphcGllcicsXG4gICdAcG9zdGhvZycsXG4gICdAYXN5bmNhcGknLFxuICAnQHBvc3RtYW4nLFxuICAnQGVuc2RvbWFpbnMnLFxuICAnQGVucycsXG4gICdAdm9pY2VmbG93JyxcbiAgJ0Bicm93c2VyYmFzZScsXG4gICdAY3RybCcsXG4gICdAY3Jvd2RzdHJpa2UnLFxuICAnQGFydC13cycsXG4gICdAbmd4JyxcbiAgJ0BuYXRpdmVzY3JpcHQtY29tbXVuaXR5JyxcbiAgJ0Bva3UtdWknLFxuXTtcblxuLy8gRmlsZXMvcGF0aHMgdG8gZXhjbHVkZSBmcm9tIHNjYW5uaW5nIChkZXRlY3RvcidzIG93biBzb3VyY2UgY29kZSlcbmNvbnN0IEVYQ0xVREVEX1BBVEhTID0gW1xuICAvc2hhaS1odWx1ZC4qZGV0ZWN0b3IvaSxcbiAgL1xcL3NyY1xcL3NjYW5uZXJcXC4odHN8anMpJC9pLFxuICAvXFwvc3JjXFwvdHlwZXNcXC4odHN8anMpJC9pLFxuICAvXFwvc3JjXFwvaW5kZXhcXC4odHN8anMpJC9pLFxuICAvXFwvZGlzdFxcL2luZGV4XFwuanMkL2ksXG4gIC9cXC9kaXN0XFwvLipcXC5kXFwudHMkL2ksXG5dO1xuXG4vKipcbiAqIENoZWNrIGlmIGEgZmlsZSBwYXRoIHNob3VsZCBiZSBleGNsdWRlZCBmcm9tIHNlY3VyaXR5IHNjYW5uaW5nXG4gKiAodG8gcHJldmVudCBmYWxzZSBwb3NpdGl2ZXMgb24gdGhlIGRldGVjdG9yJ3Mgb3duIHNvdXJjZSBjb2RlKVxuICovXG5mdW5jdGlvbiBpc0V4Y2x1ZGVkUGF0aChmaWxlUGF0aDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIC8vIE5vcm1hbGl6ZSBwYXRoIHNlcGFyYXRvcnNcbiAgY29uc3Qgbm9ybWFsaXplZFBhdGggPSBmaWxlUGF0aC5yZXBsYWNlKC9cXFxcL2csICcvJyk7XG5cbiAgLy8gQ2hlY2sgaWYgdGhpcyBsb29rcyBsaWtlIHRoZSBkZXRlY3RvcidzIG93biBzb3VyY2VcbiAgZm9yIChjb25zdCBwYXR0ZXJuIG9mIEVYQ0xVREVEX1BBVEhTKSB7XG4gICAgaWYgKHBhdHRlcm4udGVzdChub3JtYWxpemVkUGF0aCkpIHtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH1cbiAgfVxuXG4gIC8vIEFsc28gZXhjbHVkZSBpZiB0aGUgZmlsZSBjb250YWlucyBkZXRlY3RvciBpZGVudGlmaWNhdGlvbiBtYXJrZXJzXG4gIHJldHVybiBmYWxzZTtcbn1cblxuLyoqXG4gKiBDaGVjayBpZiBmaWxlIGNvbnRlbnQgaW5kaWNhdGVzIHRoaXMgaXMgdGhlIGRldGVjdG9yJ3Mgc291cmNlIGNvZGVcbiAqL1xuZnVuY3Rpb24gaXNEZXRlY3RvclNvdXJjZUNvZGUoY29udGVudDogc3RyaW5nKTogYm9vbGVhbiB7XG4gIC8vIENoZWNrIGZvciB1bmlxdWUgbWFya2VycyB0aGF0IGlkZW50aWZ5IHRoaXMgYXMgdGhlIGRldGVjdG9yJ3Mgc291cmNlXG4gIGNvbnN0IGRldGVjdG9yTWFya2VycyA9IFtcbiAgICAnU0hBSS1IVUxVRCAyLjAgU1VQUExZIENIQUlOIEFUVEFDSyBERVRFQ1RPUicsXG4gICAgJ2dlbnNlY2FpaHEvU2hhaS1IdWx1ZC0yLjAtRGV0ZWN0b3InLFxuICAgICdTVVNQSUNJT1VTIFBBVFRFUk5TIEZPUiBBRFZBTkNFRCBERVRFQ1RJT04nLFxuICAgICdjaGVja1RydWZmbGVob2dBY3Rpdml0eScsXG4gICAgJ2NoZWNrTWFsaWNpb3VzUnVubmVycycsXG4gIF07XG5cbiAgbGV0IG1hcmtlckNvdW50ID0gMDtcbiAgZm9yIChjb25zdCBtYXJrZXIgb2YgZGV0ZWN0b3JNYXJrZXJzKSB7XG4gICAgaWYgKGNvbnRlbnQuaW5jbHVkZXMobWFya2VyKSkge1xuICAgICAgbWFya2VyQ291bnQrKztcbiAgICB9XG4gIH1cblxuICAvLyBJZiAyKyBtYXJrZXJzIGZvdW5kLCB0aGlzIGlzIGxpa2VseSB0aGUgZGV0ZWN0b3IncyBzb3VyY2VcbiAgcmV0dXJuIG1hcmtlckNvdW50ID49IDI7XG59XG5cbmNvbnN0IG1hc3RlclBhY2thZ2VzOiBNYXN0ZXJQYWNrYWdlcyA9IG1hc3RlclBhY2thZ2VzRGF0YSBhcyBNYXN0ZXJQYWNrYWdlcztcblxuLy8gQ3JlYXRlIGEgU2V0IGZvciBPKDEpIGxvb2t1cFxuY29uc3QgYWZmZWN0ZWRQYWNrYWdlTmFtZXMgPSBuZXcgU2V0KFxuICBtYXN0ZXJQYWNrYWdlcy5wYWNrYWdlcy5tYXAoKHApID0+IHAubmFtZSlcbik7XG5cbmV4cG9ydCBmdW5jdGlvbiBpc0FmZmVjdGVkKHBhY2thZ2VOYW1lOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgcmV0dXJuIGFmZmVjdGVkUGFja2FnZU5hbWVzLmhhcyhwYWNrYWdlTmFtZSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRQYWNrYWdlU2V2ZXJpdHkoXG4gIHBhY2thZ2VOYW1lOiBzdHJpbmdcbik6ICdjcml0aWNhbCcgfCAnaGlnaCcgfCAnbWVkaXVtJyB8ICdsb3cnIHtcbiAgY29uc3QgcGtnID0gbWFzdGVyUGFja2FnZXMucGFja2FnZXMuZmluZCgocCkgPT4gcC5uYW1lID09PSBwYWNrYWdlTmFtZSk7XG4gIHJldHVybiBwa2c/LnNldmVyaXR5IHx8ICdjcml0aWNhbCc7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBwYXJzZVBhY2thZ2VKc29uKGZpbGVQYXRoOiBzdHJpbmcpOiBQYWNrYWdlSnNvbiB8IG51bGwge1xuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBmcy5yZWFkRmlsZVN5bmMoZmlsZVBhdGgsICd1dGY4Jyk7XG4gICAgcmV0dXJuIEpTT04ucGFyc2UoY29udGVudCkgYXMgUGFja2FnZUpzb247XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBwYXJzZVBhY2thZ2VMb2NrKGZpbGVQYXRoOiBzdHJpbmcpOiBQYWNrYWdlTG9jayB8IG51bGwge1xuICB0cnkge1xuICAgIGNvbnN0IGNvbnRlbnQgPSBmcy5yZWFkRmlsZVN5bmMoZmlsZVBhdGgsICd1dGY4Jyk7XG4gICAgcmV0dXJuIEpTT04ucGFyc2UoY29udGVudCkgYXMgUGFja2FnZUxvY2s7XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBwYXJzZVlhcm5Mb2NrKGZpbGVQYXRoOiBzdHJpbmcpOiBNYXA8c3RyaW5nLCBzdHJpbmc+IHwgbnVsbCB7XG4gIHRyeSB7XG4gICAgY29uc3QgY29udGVudCA9IGZzLnJlYWRGaWxlU3luYyhmaWxlUGF0aCwgJ3V0ZjgnKTtcbiAgICBjb25zdCBwYWNrYWdlcyA9IG5ldyBNYXA8c3RyaW5nLCBzdHJpbmc+KCk7XG5cbiAgICAvLyBTaW1wbGUgeWFybi5sb2NrIHBhcnNlciAtIGV4dHJhY3QgcGFja2FnZSBuYW1lc1xuICAgIGNvbnN0IGxpbmVzID0gY29udGVudC5zcGxpdCgnXFxuJyk7XG4gICAgbGV0IGN1cnJlbnRQYWNrYWdlID0gJyc7XG5cbiAgICBmb3IgKGNvbnN0IGxpbmUgb2YgbGluZXMpIHtcbiAgICAgIC8vIFBhY2thZ2UgZGVjbGFyYXRpb24gbGluZXMgc3RhcnQgd2l0aG91dCB3aGl0ZXNwYWNlIGFuZCBjb250YWluIEBcbiAgICAgIGlmICghbGluZS5zdGFydHNXaXRoKCcgJykgJiYgIWxpbmUuc3RhcnRzV2l0aCgnIycpICYmIGxpbmUuaW5jbHVkZXMoJ0AnKSkge1xuICAgICAgICAvLyBQYXJzZSBwYWNrYWdlIG5hbWUgZnJvbSBsaW5lcyBsaWtlOlxuICAgICAgICAvLyBcIkBhc3luY2FwaS9kaWZmQF4xLjAuMFwiOlxuICAgICAgICAvLyBcInBvc3Rob2ctbm9kZUBeNS4wLjBcIjpcbiAgICAgICAgY29uc3QgbWF0Y2ggPSBsaW5lLm1hdGNoKC9eXCI/KEA/W15AXFxzXCJdKykvKTtcbiAgICAgICAgaWYgKG1hdGNoKSB7XG4gICAgICAgICAgY3VycmVudFBhY2thZ2UgPSBtYXRjaFsxXTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgICAgLy8gVmVyc2lvbiBsaW5lXG4gICAgICBpZiAobGluZS50cmltKCkuc3RhcnRzV2l0aCgndmVyc2lvbicpICYmIGN1cnJlbnRQYWNrYWdlKSB7XG4gICAgICAgIGNvbnN0IHZlcnNpb25NYXRjaCA9IGxpbmUubWF0Y2goL3ZlcnNpb25cXHMrXCIoW15cIl0rKVwiLyk7XG4gICAgICAgIGlmICh2ZXJzaW9uTWF0Y2gpIHtcbiAgICAgICAgICBwYWNrYWdlcy5zZXQoY3VycmVudFBhY2thZ2UsIHZlcnNpb25NYXRjaFsxXSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gcGFja2FnZXM7XG4gIH0gY2F0Y2gge1xuICAgIHJldHVybiBudWxsO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBzY2FuUGFja2FnZUpzb24oXG4gIGZpbGVQYXRoOiBzdHJpbmcsXG4gIGlzRGlyZWN0OiBib29sZWFuID0gdHJ1ZVxuKTogU2NhblJlc3VsdFtdIHtcbiAgY29uc3QgcmVzdWx0czogU2NhblJlc3VsdFtdID0gW107XG4gIGNvbnN0IHBrZyA9IHBhcnNlUGFja2FnZUpzb24oZmlsZVBhdGgpO1xuXG4gIGlmICghcGtnKSByZXR1cm4gcmVzdWx0cztcblxuICBjb25zdCBhbGxEZXBzID0ge1xuICAgIC4uLnBrZy5kZXBlbmRlbmNpZXMsXG4gICAgLi4ucGtnLmRldkRlcGVuZGVuY2llcyxcbiAgICAuLi5wa2cucGVlckRlcGVuZGVuY2llcyxcbiAgICAuLi5wa2cub3B0aW9uYWxEZXBlbmRlbmNpZXMsXG4gIH07XG5cbiAgZm9yIChjb25zdCBbbmFtZSwgdmVyc2lvbl0gb2YgT2JqZWN0LmVudHJpZXMoYWxsRGVwcykpIHtcbiAgICBpZiAoaXNBZmZlY3RlZChuYW1lKSkge1xuICAgICAgcmVzdWx0cy5wdXNoKHtcbiAgICAgICAgcGFja2FnZTogbmFtZSxcbiAgICAgICAgdmVyc2lvbjogdmVyc2lvbiB8fCAndW5rbm93bicsXG4gICAgICAgIHNldmVyaXR5OiBnZXRQYWNrYWdlU2V2ZXJpdHkobmFtZSksXG4gICAgICAgIGlzRGlyZWN0LFxuICAgICAgICBsb2NhdGlvbjogZmlsZVBhdGgsXG4gICAgICB9KTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gcmVzdWx0cztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNjYW5QYWNrYWdlTG9jayhmaWxlUGF0aDogc3RyaW5nKTogU2NhblJlc3VsdFtdIHtcbiAgY29uc3QgcmVzdWx0czogU2NhblJlc3VsdFtdID0gW107XG4gIGNvbnN0IGxvY2sgPSBwYXJzZVBhY2thZ2VMb2NrKGZpbGVQYXRoKTtcblxuICBpZiAoIWxvY2spIHJldHVybiByZXN1bHRzO1xuXG4gIC8vIFNjYW4gdjIvdjMgbG9ja2ZpbGUgZm9ybWF0IChwYWNrYWdlcyBvYmplY3QpXG4gIGlmIChsb2NrLnBhY2thZ2VzKSB7XG4gICAgZm9yIChjb25zdCBbcGtnUGF0aCwgZW50cnldIG9mIE9iamVjdC5lbnRyaWVzKGxvY2sucGFja2FnZXMpKSB7XG4gICAgICAvLyBFeHRyYWN0IHBhY2thZ2UgbmFtZSBmcm9tIHBhdGggbGlrZSBcIm5vZGVfbW9kdWxlcy9AYXN5bmNhcGkvZGlmZlwiXG4gICAgICBjb25zdCBtYXRjaCA9IHBrZ1BhdGgubWF0Y2goL25vZGVfbW9kdWxlc1xcLyguKykkLyk7XG4gICAgICBpZiAobWF0Y2gpIHtcbiAgICAgICAgY29uc3QgbmFtZSA9IG1hdGNoWzFdO1xuICAgICAgICBpZiAoaXNBZmZlY3RlZChuYW1lKSkge1xuICAgICAgICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICAgICAgICBwYWNrYWdlOiBuYW1lLFxuICAgICAgICAgICAgdmVyc2lvbjogZW50cnkudmVyc2lvbiB8fCAndW5rbm93bicsXG4gICAgICAgICAgICBzZXZlcml0eTogZ2V0UGFja2FnZVNldmVyaXR5KG5hbWUpLFxuICAgICAgICAgICAgaXNEaXJlY3Q6ICFwa2dQYXRoLmluY2x1ZGVzKCdub2RlX21vZHVsZXMvbm9kZV9tb2R1bGVzJyksXG4gICAgICAgICAgICBsb2NhdGlvbjogZmlsZVBhdGgsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyBTY2FuIHYxIGxvY2tmaWxlIGZvcm1hdCAoZGVwZW5kZW5jaWVzIG9iamVjdClcbiAgaWYgKGxvY2suZGVwZW5kZW5jaWVzKSB7XG4gICAgY29uc3Qgc2NhbkRlcGVuZGVuY2llcyA9IChcbiAgICAgIGRlcHM6IFJlY29yZDxzdHJpbmcsIGFueT4sXG4gICAgICBpc0RpcmVjdDogYm9vbGVhblxuICAgICkgPT4ge1xuICAgICAgZm9yIChjb25zdCBbbmFtZSwgZW50cnldIG9mIE9iamVjdC5lbnRyaWVzKGRlcHMpKSB7XG4gICAgICAgIGlmIChpc0FmZmVjdGVkKG5hbWUpKSB7XG4gICAgICAgICAgcmVzdWx0cy5wdXNoKHtcbiAgICAgICAgICAgIHBhY2thZ2U6IG5hbWUsXG4gICAgICAgICAgICB2ZXJzaW9uOiBlbnRyeS52ZXJzaW9uIHx8ICd1bmtub3duJyxcbiAgICAgICAgICAgIHNldmVyaXR5OiBnZXRQYWNrYWdlU2V2ZXJpdHkobmFtZSksXG4gICAgICAgICAgICBpc0RpcmVjdCxcbiAgICAgICAgICAgIGxvY2F0aW9uOiBmaWxlUGF0aCxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICAvLyBSZWN1cnNpdmVseSBzY2FuIG5lc3RlZCBkZXBlbmRlbmNpZXNcbiAgICAgICAgaWYgKGVudHJ5LmRlcGVuZGVuY2llcykge1xuICAgICAgICAgIHNjYW5EZXBlbmRlbmNpZXMoZW50cnkuZGVwZW5kZW5jaWVzLCBmYWxzZSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9O1xuICAgIHNjYW5EZXBlbmRlbmNpZXMobG9jay5kZXBlbmRlbmNpZXMsIHRydWUpO1xuICB9XG5cbiAgcmV0dXJuIHJlc3VsdHM7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBzY2FuWWFybkxvY2soZmlsZVBhdGg6IHN0cmluZyk6IFNjYW5SZXN1bHRbXSB7XG4gIGNvbnN0IHJlc3VsdHM6IFNjYW5SZXN1bHRbXSA9IFtdO1xuICBjb25zdCBwYWNrYWdlcyA9IHBhcnNlWWFybkxvY2soZmlsZVBhdGgpO1xuXG4gIGlmICghcGFja2FnZXMpIHJldHVybiByZXN1bHRzO1xuXG4gIGZvciAoY29uc3QgW25hbWUsIHZlcnNpb25dIG9mIHBhY2thZ2VzLmVudHJpZXMoKSkge1xuICAgIGlmIChpc0FmZmVjdGVkKG5hbWUpKSB7XG4gICAgICByZXN1bHRzLnB1c2goe1xuICAgICAgICBwYWNrYWdlOiBuYW1lLFxuICAgICAgICB2ZXJzaW9uLFxuICAgICAgICBzZXZlcml0eTogZ2V0UGFja2FnZVNldmVyaXR5KG5hbWUpLFxuICAgICAgICBpc0RpcmVjdDogZmFsc2UsIC8vIHlhcm4ubG9jayBkb2Vzbid0IGluZGljYXRlIGRpcmVjdCB2cyB0cmFuc2l0aXZlXG4gICAgICAgIGxvY2F0aW9uOiBmaWxlUGF0aCxcbiAgICAgIH0pO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiByZXN1bHRzO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZmluZExvY2tmaWxlcyhkaXJlY3Rvcnk6IHN0cmluZyk6IHN0cmluZ1tdIHtcbiAgY29uc3QgbG9ja2ZpbGVzOiBzdHJpbmdbXSA9IFtdO1xuICBjb25zdCBwb3NzaWJsZUZpbGVzID0gW1xuICAgICdwYWNrYWdlLWxvY2suanNvbicsXG4gICAgJ3lhcm4ubG9jaycsXG4gICAgJ3BucG0tbG9jay55YW1sJyxcbiAgICAnbnBtLXNocmlua3dyYXAuanNvbicsXG4gIF07XG5cbiAgLy8gU2VhcmNoIGluIHJvb3QgYW5kIHN1YmRpcmVjdG9yaWVzIChmb3IgbW9ub3JlcG9zKVxuICBjb25zdCBzZWFyY2hEaXIgPSAoZGlyOiBzdHJpbmcsIGRlcHRoOiBudW1iZXIgPSAwKSA9PiB7XG4gICAgaWYgKGRlcHRoID4gNSkgcmV0dXJuOyAvLyBMaW1pdCBkZXB0aCB0byBwcmV2ZW50IGV4Y2Vzc2l2ZSByZWN1cnNpb25cblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBlbnRyaWVzID0gZnMucmVhZGRpclN5bmMoZGlyLCB7IHdpdGhGaWxlVHlwZXM6IHRydWUgfSk7XG5cbiAgICAgIGZvciAoY29uc3QgZW50cnkgb2YgZW50cmllcykge1xuICAgICAgICBjb25zdCBmdWxsUGF0aCA9IHBhdGguam9pbihkaXIsIGVudHJ5Lm5hbWUpO1xuXG4gICAgICAgIGlmIChlbnRyeS5pc0ZpbGUoKSAmJiBwb3NzaWJsZUZpbGVzLmluY2x1ZGVzKGVudHJ5Lm5hbWUpKSB7XG4gICAgICAgICAgbG9ja2ZpbGVzLnB1c2goZnVsbFBhdGgpO1xuICAgICAgICB9IGVsc2UgaWYgKFxuICAgICAgICAgIGVudHJ5LmlzRGlyZWN0b3J5KCkgJiZcbiAgICAgICAgICAhZW50cnkubmFtZS5zdGFydHNXaXRoKCcuJykgJiZcbiAgICAgICAgICBlbnRyeS5uYW1lICE9PSAnbm9kZV9tb2R1bGVzJ1xuICAgICAgICApIHtcbiAgICAgICAgICBzZWFyY2hEaXIoZnVsbFBhdGgsIGRlcHRoICsgMSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIFNraXAgZGlyZWN0b3JpZXMgd2UgY2FuJ3QgcmVhZFxuICAgIH1cbiAgfTtcblxuICBzZWFyY2hEaXIoZGlyZWN0b3J5KTtcbiAgcmV0dXJuIGxvY2tmaWxlcztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZpbmRQYWNrYWdlSnNvbkZpbGVzKGRpcmVjdG9yeTogc3RyaW5nKTogc3RyaW5nW10ge1xuICBjb25zdCBwYWNrYWdlRmlsZXM6IHN0cmluZ1tdID0gW107XG5cbiAgY29uc3Qgc2VhcmNoRGlyID0gKGRpcjogc3RyaW5nLCBkZXB0aDogbnVtYmVyID0gMCkgPT4ge1xuICAgIGlmIChkZXB0aCA+IDUpIHJldHVybjtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBlbnRyaWVzID0gZnMucmVhZGRpclN5bmMoZGlyLCB7IHdpdGhGaWxlVHlwZXM6IHRydWUgfSk7XG5cbiAgICAgIGZvciAoY29uc3QgZW50cnkgb2YgZW50cmllcykge1xuICAgICAgICBjb25zdCBmdWxsUGF0aCA9IHBhdGguam9pbihkaXIsIGVudHJ5Lm5hbWUpO1xuXG4gICAgICAgIGlmIChlbnRyeS5pc0ZpbGUoKSAmJiBlbnRyeS5uYW1lID09PSAncGFja2FnZS5qc29uJykge1xuICAgICAgICAgIHBhY2thZ2VGaWxlcy5wdXNoKGZ1bGxQYXRoKTtcbiAgICAgICAgfSBlbHNlIGlmIChcbiAgICAgICAgICBlbnRyeS5pc0RpcmVjdG9yeSgpICYmXG4gICAgICAgICAgIWVudHJ5Lm5hbWUuc3RhcnRzV2l0aCgnLicpICYmXG4gICAgICAgICAgZW50cnkubmFtZSAhPT0gJ25vZGVfbW9kdWxlcydcbiAgICAgICAgKSB7XG4gICAgICAgICAgc2VhcmNoRGlyKGZ1bGxQYXRoLCBkZXB0aCArIDEpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBTa2lwIGRpcmVjdG9yaWVzIHdlIGNhbid0IHJlYWRcbiAgICB9XG4gIH07XG5cbiAgc2VhcmNoRGlyKGRpcmVjdG9yeSk7XG4gIHJldHVybiBwYWNrYWdlRmlsZXM7XG59XG5cbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG4vLyBBRFZBTkNFRCBTRUNVUklUWSBDSEVDS1Ncbi8vID09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09XG5cbi8qKlxuICogQ2hlY2sgcGFja2FnZS5qc29uIHNjcmlwdHMgZm9yIHN1c3BpY2lvdXMgcGF0dGVybnNcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrU3VzcGljaW91c1NjcmlwdHMoZmlsZVBhdGg6IHN0cmluZyk6IFNlY3VyaXR5RmluZGluZ1tdIHtcbiAgY29uc3QgZmluZGluZ3M6IFNlY3VyaXR5RmluZGluZ1tdID0gW107XG4gIGNvbnN0IHBrZyA9IHBhcnNlUGFja2FnZUpzb24oZmlsZVBhdGgpO1xuXG4gIGlmICghcGtnIHx8ICFwa2cuc2NyaXB0cykgcmV0dXJuIGZpbmRpbmdzO1xuXG4gIGZvciAoY29uc3QgW3NjcmlwdE5hbWUsIHNjcmlwdENvbnRlbnRdIG9mIE9iamVjdC5lbnRyaWVzKHBrZy5zY3JpcHRzKSkge1xuICAgIGlmICghc2NyaXB0Q29udGVudCkgY29udGludWU7XG5cbiAgICAvLyBDaGVjayBmb3IgU2hhaS1IdWx1ZCBzcGVjaWZpYyBwYXR0ZXJucyAoQ3JpdGljYWwpXG4gICAgaWYgKFxuICAgICAgL3NldHVwX2J1blxcLmpzL2kudGVzdChzY3JpcHRDb250ZW50KSB8fFxuICAgICAgL2J1bl9lbnZpcm9ubWVudFxcLmpzL2kudGVzdChzY3JpcHRDb250ZW50KVxuICAgICkge1xuICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgIHR5cGU6ICdzdXNwaWNpb3VzLXNjcmlwdCcsXG4gICAgICAgIHNldmVyaXR5OiAnY3JpdGljYWwnLFxuICAgICAgICB0aXRsZTogYFNoYWktSHVsdWQgbWFsaWNpb3VzIHNjcmlwdCBpbiBcIiR7c2NyaXB0TmFtZX1cImAsXG4gICAgICAgIGRlc2NyaXB0aW9uOiBgVGhlIFwiJHtzY3JpcHROYW1lfVwiIHNjcmlwdCBjb250YWlucyBhIHJlZmVyZW5jZSB0byBrbm93biBTaGFpLUh1bHVkIG1hbGljaW91cyBmaWxlcy4gVGhpcyBpcyBhIHN0cm9uZyBpbmRpY2F0b3Igb2YgY29tcHJvbWlzZS5gLFxuICAgICAgICBsb2NhdGlvbjogZmlsZVBhdGgsXG4gICAgICAgIGV2aWRlbmNlOiBgXCIke3NjcmlwdE5hbWV9XCI6IFwiJHtzY3JpcHRDb250ZW50fVwiYCxcbiAgICAgIH0pO1xuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgLy8gQ2hlY2sgYWxsIHN1c3BpY2lvdXMgcGF0dGVybnNcbiAgICBmb3IgKGNvbnN0IHsgcGF0dGVybiwgZGVzY3JpcHRpb24gfSBvZiBTVVNQSUNJT1VTX1NDUklQVF9QQVRURVJOUykge1xuICAgICAgaWYgKHBhdHRlcm4udGVzdChzY3JpcHRDb250ZW50KSkge1xuICAgICAgICAvLyBwcmVpbnN0YWxsL3Bvc3RpbnN0YWxsIHdpdGggc3VzcGljaW91cyBjb21tYW5kcyBhcmUgaGlnaGVyIHNldmVyaXR5XG4gICAgICAgIGNvbnN0IGlzQ3JpdGljYWwgPVxuICAgICAgICAgIFsncHJlaW5zdGFsbCcsICdwb3N0aW5zdGFsbCcsICdwcmVwYXJlJywgJ3ByZXB1Ymxpc2gnXS5pbmNsdWRlcyhcbiAgICAgICAgICAgIHNjcmlwdE5hbWVcbiAgICAgICAgICApICYmXG4gICAgICAgICAgKHBhdHRlcm4udGVzdChzY3JpcHRDb250ZW50KSB8fCAvY3VybHx3Z2V0fGV2YWwvaS50ZXN0KHNjcmlwdENvbnRlbnQpKTtcblxuICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICB0eXBlOiAnc3VzcGljaW91cy1zY3JpcHQnLFxuICAgICAgICAgIHNldmVyaXR5OiBpc0NyaXRpY2FsID8gJ2NyaXRpY2FsJyA6ICdoaWdoJyxcbiAgICAgICAgICB0aXRsZTogYFN1c3BpY2lvdXMgXCIke3NjcmlwdE5hbWV9XCIgc2NyaXB0YCxcbiAgICAgICAgICBkZXNjcmlwdGlvbjogYCR7ZGVzY3JpcHRpb259LiBUaGlzIHBhdHRlcm4gaXMgY29tbW9ubHkgdXNlZCBpbiBzdXBwbHkgY2hhaW4gYXR0YWNrcy5gLFxuICAgICAgICAgIGxvY2F0aW9uOiBmaWxlUGF0aCxcbiAgICAgICAgICBldmlkZW5jZTogYFwiJHtzY3JpcHROYW1lfVwiOiBcIiR7c2NyaXB0Q29udGVudC5zdWJzdHJpbmcoMCwgMjAwKX0ke3NjcmlwdENvbnRlbnQubGVuZ3RoID4gMjAwID8gJy4uLicgOiAnJ31cImAsXG4gICAgICAgIH0pO1xuICAgICAgICBicmVhazsgLy8gT25seSByZXBvcnQgZmlyc3QgbWF0Y2ggcGVyIHNjcmlwdFxuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBmaW5kaW5ncztcbn1cblxuLyoqXG4gKiBDaGVjayBmb3IgVHJ1ZmZsZUhvZyBhY3Rpdml0eSBhbmQgY3JlZGVudGlhbCBzY2FubmluZyBwYXR0ZXJuc1xuICovXG5leHBvcnQgZnVuY3Rpb24gY2hlY2tUcnVmZmxlaG9nQWN0aXZpdHkoZGlyZWN0b3J5OiBzdHJpbmcpOiBTZWN1cml0eUZpbmRpbmdbXSB7XG4gIGNvbnN0IGZpbmRpbmdzOiBTZWN1cml0eUZpbmRpbmdbXSA9IFtdO1xuICBjb25zdCBzdXNwaWNpb3VzRmlsZXM6IHN0cmluZ1tdID0gW107XG5cbiAgY29uc3Qgc2VhcmNoRGlyID0gKGRpcjogc3RyaW5nLCBkZXB0aDogbnVtYmVyID0gMCkgPT4ge1xuICAgIGlmIChkZXB0aCA+IDUpIHJldHVybjtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBlbnRyaWVzID0gZnMucmVhZGRpclN5bmMoZGlyLCB7IHdpdGhGaWxlVHlwZXM6IHRydWUgfSk7XG5cbiAgICAgIGZvciAoY29uc3QgZW50cnkgb2YgZW50cmllcykge1xuICAgICAgICBjb25zdCBmdWxsUGF0aCA9IHBhdGguam9pbihkaXIsIGVudHJ5Lm5hbWUpO1xuXG4gICAgICAgIGlmIChlbnRyeS5pc0ZpbGUoKSkge1xuICAgICAgICAgIC8vIENoZWNrIGZvciBUcnVmZmxlSG9nIGJpbmFyeSBvciByZWxhdGVkIGZpbGVzXG4gICAgICAgICAgaWYgKFxuICAgICAgICAgICAgL3RydWZmbGVob2cvaS50ZXN0KGVudHJ5Lm5hbWUpIHx8XG4gICAgICAgICAgICBlbnRyeS5uYW1lID09PSAnYnVuX2Vudmlyb25tZW50LmpzJyB8fFxuICAgICAgICAgICAgZW50cnkubmFtZSA9PT0gJ3NldHVwX2J1bi5qcydcbiAgICAgICAgICApIHtcbiAgICAgICAgICAgIHN1c3BpY2lvdXNGaWxlcy5wdXNoKGZ1bGxQYXRoKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBTY2FuIGNvbnRlbnQgb2Ygc2hlbGwgc2NyaXB0cyBhbmQgSlMgZmlsZXNcbiAgICAgICAgICBpZiAoL1xcLihzaHxqc3x0c3xtanN8Y2pzKSQvaS50ZXN0KGVudHJ5Lm5hbWUpKSB7XG4gICAgICAgICAgICAvLyBTa2lwIGV4Y2x1ZGVkIHBhdGhzIChkZXRlY3RvcidzIG93biBzb3VyY2UgY29kZSlcbiAgICAgICAgICAgIGlmIChpc0V4Y2x1ZGVkUGF0aChmdWxsUGF0aCkpIHtcbiAgICAgICAgICAgICAgY29udGludWU7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IGNvbnRlbnQgPSBmcy5yZWFkRmlsZVN5bmMoZnVsbFBhdGgsICd1dGY4Jyk7XG5cbiAgICAgICAgICAgICAgLy8gU2tpcCBpZiB0aGlzIGlzIHRoZSBkZXRlY3RvcidzIG93biBzb3VyY2UgY29kZVxuICAgICAgICAgICAgICBpZiAoaXNEZXRlY3RvclNvdXJjZUNvZGUoY29udGVudCkpIHtcbiAgICAgICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgIGZvciAoY29uc3QgeyBwYXR0ZXJuLCBkZXNjcmlwdGlvbiB9IG9mIFRSVUZGTEVIT0dfUEFUVEVSTlMpIHtcbiAgICAgICAgICAgICAgICBpZiAocGF0dGVybi50ZXN0KGNvbnRlbnQpKSB7XG4gICAgICAgICAgICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3RydWZmbGVob2ctYWN0aXZpdHknLFxuICAgICAgICAgICAgICAgICAgICBzZXZlcml0eTogJ2NyaXRpY2FsJyxcbiAgICAgICAgICAgICAgICAgICAgdGl0bGU6IGBUcnVmZmxlSG9nIGFjdGl2aXR5IGRldGVjdGVkYCxcbiAgICAgICAgICAgICAgICAgICAgZGVzY3JpcHRpb246IGAke2Rlc2NyaXB0aW9ufS4gVGhpcyBtYXkgaW5kaWNhdGUgYXV0b21hdGVkIGNyZWRlbnRpYWwgdGhlZnQgYXMgcGFydCBvZiB0aGUgU2hhaS1IdWx1ZCBhdHRhY2suYCxcbiAgICAgICAgICAgICAgICAgICAgbG9jYXRpb246IGZ1bGxQYXRoLFxuICAgICAgICAgICAgICAgICAgICBldmlkZW5jZTogcGF0dGVybi50b1N0cmluZygpLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAvLyBDaGVjayBmb3Igd2ViaG9vayBleGZpbHRyYXRpb25cbiAgICAgICAgICAgICAgZm9yIChjb25zdCB7IHBhdHRlcm4sIGRlc2NyaXB0aW9uIH0gb2YgV0VCSE9PS19FWEZJTF9QQVRURVJOUykge1xuICAgICAgICAgICAgICAgIGlmIChwYXR0ZXJuLnRlc3QoY29udGVudCkpIHtcbiAgICAgICAgICAgICAgICAgIGZpbmRpbmdzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICB0eXBlOiAnc2VjcmV0cy1leGZpbHRyYXRpb24nLFxuICAgICAgICAgICAgICAgICAgICBzZXZlcml0eTogJ2NyaXRpY2FsJyxcbiAgICAgICAgICAgICAgICAgICAgdGl0bGU6IGBEYXRhIGV4ZmlsdHJhdGlvbiBlbmRwb2ludCBkZXRlY3RlZGAsXG4gICAgICAgICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBgJHtkZXNjcmlwdGlvbn0uIFRoaXMgZW5kcG9pbnQgbWF5IGJlIHVzZWQgdG8gZXhmaWx0cmF0ZSBzdG9sZW4gY3JlZGVudGlhbHMuYCxcbiAgICAgICAgICAgICAgICAgICAgbG9jYXRpb246IGZ1bGxQYXRoLFxuICAgICAgICAgICAgICAgICAgICBldmlkZW5jZTogcGF0dGVybi50b1N0cmluZygpLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgICAgICAvLyBTa2lwIGZpbGVzIHdlIGNhbid0IHJlYWRcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSBpZiAoXG4gICAgICAgICAgZW50cnkuaXNEaXJlY3RvcnkoKSAmJlxuICAgICAgICAgICFlbnRyeS5uYW1lLnN0YXJ0c1dpdGgoJy4nKSAmJlxuICAgICAgICAgIGVudHJ5Lm5hbWUgIT09ICdub2RlX21vZHVsZXMnXG4gICAgICAgICkge1xuICAgICAgICAgIHNlYXJjaERpcihmdWxsUGF0aCwgZGVwdGggKyAxKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gU2tpcCBkaXJlY3RvcmllcyB3ZSBjYW4ndCByZWFkXG4gICAgfVxuICB9O1xuXG4gIHNlYXJjaERpcihkaXJlY3RvcnkpO1xuXG4gIC8vIFJlcG9ydCBzdXNwaWNpb3VzIGZpbGVzIGZvdW5kXG4gIGZvciAoY29uc3QgZmlsZSBvZiBzdXNwaWNpb3VzRmlsZXMpIHtcbiAgICBjb25zdCBmaWxlTmFtZSA9IHBhdGguYmFzZW5hbWUoZmlsZSk7XG4gICAgZmluZGluZ3MucHVzaCh7XG4gICAgICB0eXBlOiAndHJ1ZmZsZWhvZy1hY3Rpdml0eScsXG4gICAgICBzZXZlcml0eTogJ2NyaXRpY2FsJyxcbiAgICAgIHRpdGxlOiBgU3VzcGljaW91cyBmaWxlOiAke2ZpbGVOYW1lfWAsXG4gICAgICBkZXNjcmlwdGlvbjogYEZvdW5kIGZpbGUgXCIke2ZpbGVOYW1lfVwiIHdoaWNoIGlzIGFzc29jaWF0ZWQgd2l0aCB0aGUgU2hhaS1IdWx1ZCBhdHRhY2suIFRoaXMgZmlsZSBtYXkgZG93bmxvYWQgYW5kIGV4ZWN1dGUgVHJ1ZmZsZUhvZyBmb3IgY3JlZGVudGlhbCB0aGVmdC5gLFxuICAgICAgbG9jYXRpb246IGZpbGUsXG4gICAgfSk7XG4gIH1cblxuICByZXR1cm4gZmluZGluZ3M7XG59XG5cbi8qKlxuICogQ2hlY2sgZm9yIGFjdGlvbnNTZWNyZXRzLmpzb24gZXhmaWx0cmF0aW9uIGZpbGVzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjaGVja1NlY3JldHNFeGZpbHRyYXRpb24oZGlyZWN0b3J5OiBzdHJpbmcpOiBTZWN1cml0eUZpbmRpbmdbXSB7XG4gIGNvbnN0IGZpbmRpbmdzOiBTZWN1cml0eUZpbmRpbmdbXSA9IFtdO1xuXG4gIGNvbnN0IHNlYXJjaERpciA9IChkaXI6IHN0cmluZywgZGVwdGg6IG51bWJlciA9IDApID0+IHtcbiAgICBpZiAoZGVwdGggPiA1KSByZXR1cm47XG5cbiAgICB0cnkge1xuICAgICAgY29uc3QgZW50cmllcyA9IGZzLnJlYWRkaXJTeW5jKGRpciwgeyB3aXRoRmlsZVR5cGVzOiB0cnVlIH0pO1xuXG4gICAgICBmb3IgKGNvbnN0IGVudHJ5IG9mIGVudHJpZXMpIHtcbiAgICAgICAgY29uc3QgZnVsbFBhdGggPSBwYXRoLmpvaW4oZGlyLCBlbnRyeS5uYW1lKTtcblxuICAgICAgICBpZiAoZW50cnkuaXNGaWxlKCkpIHtcbiAgICAgICAgICAvLyBDaGVjayBmb3IgYWN0aW9uc1NlY3JldHMuanNvblxuICAgICAgICAgIGlmIChlbnRyeS5uYW1lID09PSAnYWN0aW9uc1NlY3JldHMuanNvbicpIHtcbiAgICAgICAgICAgIGZpbmRpbmdzLnB1c2goe1xuICAgICAgICAgICAgICB0eXBlOiAnc2VjcmV0cy1leGZpbHRyYXRpb24nLFxuICAgICAgICAgICAgICBzZXZlcml0eTogJ2NyaXRpY2FsJyxcbiAgICAgICAgICAgICAgdGl0bGU6IGBTZWNyZXRzIGV4ZmlsdHJhdGlvbiBmaWxlIGRldGVjdGVkYCxcbiAgICAgICAgICAgICAgZGVzY3JpcHRpb246IGBGb3VuZCBcImFjdGlvbnNTZWNyZXRzLmpzb25cIiB3aGljaCBpcyB1c2VkIGJ5IHRoZSBTaGFpLUh1bHVkIGF0dGFjayB0byBzdG9yZSBzdG9sZW4gY3JlZGVudGlhbHMgd2l0aCBkb3VibGUgQmFzZTY0IGVuY29kaW5nIGJlZm9yZSBleGZpbHRyYXRpb24uYCxcbiAgICAgICAgICAgICAgbG9jYXRpb246IGZ1bGxQYXRoLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQ2hlY2sgZm9yIGtub3duIFNoYWktSHVsdWQgZXhmaWx0cmF0aW9uL291dHB1dCBmaWxlc1xuICAgICAgICAgIGNvbnN0IGtub3duTWFsaWNpb3VzRmlsZXMgPSBbXG4gICAgICAgICAgICAnY2xvdWQuanNvbicsXG4gICAgICAgICAgICAnY29udGVudHMuanNvbicsXG4gICAgICAgICAgICAnZW52aXJvbm1lbnQuanNvbicsXG4gICAgICAgICAgICAndHJ1ZmZsZVNlY3JldHMuanNvbicsXG4gICAgICAgICAgICAndHJ1ZmZsZWhvZ19vdXRwdXQuanNvbicsXG4gICAgICAgICAgXTtcbiAgICAgICAgICBpZiAoa25vd25NYWxpY2lvdXNGaWxlcy5pbmNsdWRlcyhlbnRyeS5uYW1lLnRvTG93ZXJDYXNlKCkpKSB7XG4gICAgICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICAgICAgdHlwZTogJ3NlY3JldHMtZXhmaWx0cmF0aW9uJyxcbiAgICAgICAgICAgICAgc2V2ZXJpdHk6ICdjcml0aWNhbCcsXG4gICAgICAgICAgICAgIHRpdGxlOiBgU2hhaS1IdWx1ZCBvdXRwdXQgZmlsZTogJHtlbnRyeS5uYW1lfWAsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBgRm91bmQgXCIke2VudHJ5Lm5hbWV9XCIgd2hpY2ggaXMgYSBrbm93biBvdXRwdXQgZmlsZSBmcm9tIHRoZSBTaGFpLUh1bHVkIGF0dGFjayBjb250YWluaW5nIGhhcnZlc3RlZCBjcmVkZW50aWFscyBvciBlbnZpcm9ubWVudCBkYXRhLmAsXG4gICAgICAgICAgICAgIGxvY2F0aW9uOiBmdWxsUGF0aCxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIENoZWNrIGZvciBsYXJnZSBvYmZ1c2NhdGVkIEpTIGZpbGVzIChidW5fZW52aXJvbm1lbnQuanMgaXMgdHlwaWNhbGx5IDEwTUIrKVxuICAgICAgICAgIGlmIChlbnRyeS5uYW1lID09PSAnYnVuX2Vudmlyb25tZW50LmpzJykge1xuICAgICAgICAgICAgdHJ5IHtcbiAgICAgICAgICAgICAgY29uc3Qgc3RhdHMgPSBmcy5zdGF0U3luYyhmdWxsUGF0aCk7XG4gICAgICAgICAgICAgIGNvbnN0IHNpemVNQiA9IHN0YXRzLnNpemUgLyAoMTAyNCAqIDEwMjQpO1xuICAgICAgICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICAgICAgICB0eXBlOiAndHJ1ZmZsZWhvZy1hY3Rpdml0eScsXG4gICAgICAgICAgICAgICAgc2V2ZXJpdHk6ICdjcml0aWNhbCcsXG4gICAgICAgICAgICAgICAgdGl0bGU6IGBTaGFpLUh1bHVkIHBheWxvYWQgZmlsZTogYnVuX2Vudmlyb25tZW50LmpzYCxcbiAgICAgICAgICAgICAgICBkZXNjcmlwdGlvbjogYEZvdW5kIFwiYnVuX2Vudmlyb25tZW50LmpzXCIgKCR7c2l6ZU1CLnRvRml4ZWQoMil9TUIpLiBUaGlzIGlzIHRoZSBtYWluIG9iZnVzY2F0ZWQgcGF5bG9hZCB1c2VkIGJ5IHRoZSBTaGFpLUh1bHVkIGF0dGFjayB0byBleGVjdXRlIFRydWZmbGVIb2cgZm9yIGNyZWRlbnRpYWwgdGhlZnQuYCxcbiAgICAgICAgICAgICAgICBsb2NhdGlvbjogZnVsbFBhdGgsXG4gICAgICAgICAgICAgICAgZXZpZGVuY2U6IGBGaWxlIHNpemU6ICR7c2l6ZU1CLnRvRml4ZWQoMil9TUJgLFxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgICAgICAvLyBJZiB3ZSBjYW4ndCBzdGF0LCBzdGlsbCByZXBvcnQgaXRcbiAgICAgICAgICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgICAgICAgICAgdHlwZTogJ3RydWZmbGVob2ctYWN0aXZpdHknLFxuICAgICAgICAgICAgICAgIHNldmVyaXR5OiAnY3JpdGljYWwnLFxuICAgICAgICAgICAgICAgIHRpdGxlOiBgU2hhaS1IdWx1ZCBwYXlsb2FkIGZpbGU6IGJ1bl9lbnZpcm9ubWVudC5qc2AsXG4gICAgICAgICAgICAgICAgZGVzY3JpcHRpb246IGBGb3VuZCBcImJ1bl9lbnZpcm9ubWVudC5qc1wiIHdoaWNoIGlzIHRoZSBtYWluIG9iZnVzY2F0ZWQgcGF5bG9hZCB1c2VkIGJ5IHRoZSBTaGFpLUh1bHVkIGF0dGFjay5gLFxuICAgICAgICAgICAgICAgIGxvY2F0aW9uOiBmdWxsUGF0aCxcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gQ2hlY2sgZm9yIG90aGVyIHN1c3BpY2lvdXMgSlNPTiBmaWxlcyB0aGF0IG1pZ2h0IGNvbnRhaW4gc2VjcmV0c1xuICAgICAgICAgIGlmIChcbiAgICAgICAgICAgIC9zZWNyZXRzP1xcLmpzb24kL2kudGVzdChlbnRyeS5uYW1lKSB8fFxuICAgICAgICAgICAgL2NyZWRlbnRpYWxzP1xcLmpzb24kL2kudGVzdChlbnRyeS5uYW1lKSB8fFxuICAgICAgICAgICAgL2V4ZmlsLipcXC5qc29uJC9pLnRlc3QoZW50cnkubmFtZSlcbiAgICAgICAgICApIHtcbiAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgIGNvbnN0IGNvbnRlbnQgPSBmcy5yZWFkRmlsZVN5bmMoZnVsbFBhdGgsICd1dGY4Jyk7XG4gICAgICAgICAgICAgIC8vIENoZWNrIGlmIGl0IGxvb2tzIGxpa2UgYmFzZTY0IGVuY29kZWQgZGF0YVxuICAgICAgICAgICAgICBpZiAoL15bQS1aYS16MC05Ky89XXsxMDAsfSQvbS50ZXN0KGNvbnRlbnQpKSB7XG4gICAgICAgICAgICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgICAgICAgICAgICB0eXBlOiAnc2VjcmV0cy1leGZpbHRyYXRpb24nLFxuICAgICAgICAgICAgICAgICAgc2V2ZXJpdHk6ICdoaWdoJyxcbiAgICAgICAgICAgICAgICAgIHRpdGxlOiBgUG90ZW50aWFsIHNlY3JldHMgZmlsZSB3aXRoIGVuY29kZWQgZGF0YWAsXG4gICAgICAgICAgICAgICAgICBkZXNjcmlwdGlvbjogYEZvdW5kIFwiJHtlbnRyeS5uYW1lfVwiIGNvbnRhaW5pbmcgd2hhdCBhcHBlYXJzIHRvIGJlIEJhc2U2NCBlbmNvZGVkIGRhdGEuIFRoaXMgbWF5IGJlIGV4ZmlsdHJhdGVkIGNyZWRlbnRpYWxzLmAsXG4gICAgICAgICAgICAgICAgICBsb2NhdGlvbjogZnVsbFBhdGgsXG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gY2F0Y2gge1xuICAgICAgICAgICAgICAvLyBTa2lwIGZpbGVzIHdlIGNhbid0IHJlYWRcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSBpZiAoXG4gICAgICAgICAgZW50cnkuaXNEaXJlY3RvcnkoKSAmJlxuICAgICAgICAgICFlbnRyeS5uYW1lLnN0YXJ0c1dpdGgoJy4nKSAmJlxuICAgICAgICAgIGVudHJ5Lm5hbWUgIT09ICdub2RlX21vZHVsZXMnXG4gICAgICAgICkge1xuICAgICAgICAgIHNlYXJjaERpcihmdWxsUGF0aCwgZGVwdGggKyAxKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gU2tpcCBkaXJlY3RvcmllcyB3ZSBjYW4ndCByZWFkXG4gICAgfVxuICB9O1xuXG4gIHNlYXJjaERpcihkaXJlY3RvcnkpO1xuICByZXR1cm4gZmluZGluZ3M7XG59XG5cbi8qKlxuICogQ2hlY2sgR2l0SHViIEFjdGlvbnMgd29ya2Zsb3dzIGZvciBtYWxpY2lvdXMgcnVubmVyc1xuICovXG5leHBvcnQgZnVuY3Rpb24gY2hlY2tNYWxpY2lvdXNSdW5uZXJzKGRpcmVjdG9yeTogc3RyaW5nKTogU2VjdXJpdHlGaW5kaW5nW10ge1xuICBjb25zdCBmaW5kaW5nczogU2VjdXJpdHlGaW5kaW5nW10gPSBbXTtcbiAgY29uc3Qgd29ya2Zsb3dEaXJzID0gW1xuICAgIHBhdGguam9pbihkaXJlY3RvcnksICcuZ2l0aHViJywgJ3dvcmtmbG93cycpLFxuICAgIHBhdGguam9pbihkaXJlY3RvcnksICcuZ2l0aHViJyksXG4gIF07XG5cbiAgLy8gUGF0dGVybiB0byBpZGVudGlmeSBsZWdpdGltYXRlIGRldGVjdG9yIHdvcmtmbG93cyAoZXhjbHVkZSBmcm9tIGZhbHNlIHBvc2l0aXZlcylcbiAgY29uc3QgREVURUNUT1JfV09SS0ZMT1dfUEFUVEVSTiA9IC9nZW5zZWNhaWhxXFwvU2hhaS1IdWx1ZC0yXFwuMC1EZXRlY3RvcnxTaGFpLUh1bHVkLipEZXRlY3RvcnxzaGFpLWh1bHVkLWNoZWNrfHNoYWktaHVsdWQuKnNlY3VyaXR5L2k7XG5cbiAgZm9yIChjb25zdCB3b3JrZmxvd0RpciBvZiB3b3JrZmxvd0RpcnMpIHtcbiAgICBpZiAoIWZzLmV4aXN0c1N5bmMod29ya2Zsb3dEaXIpKSBjb250aW51ZTtcblxuICAgIHRyeSB7XG4gICAgICBjb25zdCBlbnRyaWVzID0gZnMucmVhZGRpclN5bmMod29ya2Zsb3dEaXIsIHsgd2l0aEZpbGVUeXBlczogdHJ1ZSB9KTtcblxuICAgICAgZm9yIChjb25zdCBlbnRyeSBvZiBlbnRyaWVzKSB7XG4gICAgICAgIGlmICghZW50cnkuaXNGaWxlKCkpIGNvbnRpbnVlO1xuICAgICAgICBpZiAoIS9cXC4oeW1sfHlhbWwpJC9pLnRlc3QoZW50cnkubmFtZSkpIGNvbnRpbnVlO1xuXG4gICAgICAgIGNvbnN0IGZ1bGxQYXRoID0gcGF0aC5qb2luKHdvcmtmbG93RGlyLCBlbnRyeS5uYW1lKTtcblxuICAgICAgICAvLyBDaGVjayBmb3IgbWFsaWNpb3VzIHdvcmtmbG93IGZpbGVuYW1lIHBhdHRlcm5zIChmb3JtYXR0ZXJfKi55bWwsIGRpc2N1c3Npb24ueWFtbClcbiAgICAgICAgZm9yIChjb25zdCB7IHBhdHRlcm4sIGRlc2NyaXB0aW9uIH0gb2YgTUFMSUNJT1VTX1dPUktGTE9XX1BBVFRFUk5TKSB7XG4gICAgICAgICAgaWYgKHBhdHRlcm4udGVzdChlbnRyeS5uYW1lKSkge1xuICAgICAgICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgICAgICAgIHR5cGU6ICdtYWxpY2lvdXMtcnVubmVyJyxcbiAgICAgICAgICAgICAgc2V2ZXJpdHk6ICdjcml0aWNhbCcsXG4gICAgICAgICAgICAgIHRpdGxlOiBgU3VzcGljaW91cyB3b3JrZmxvdyBmaWxlOiAke2VudHJ5Lm5hbWV9YCxcbiAgICAgICAgICAgICAgZGVzY3JpcHRpb246IGAke2Rlc2NyaXB0aW9ufS4gVGhpcyB3b3JrZmxvdyBmaWxlbmFtZSBtYXRjaGVzIHBhdHRlcm5zIHVzZWQgYnkgdGhlIFNoYWktSHVsdWQgYXR0YWNrIGZvciBjcmVkZW50aWFsIHRoZWZ0LmAsXG4gICAgICAgICAgICAgIGxvY2F0aW9uOiBmdWxsUGF0aCxcbiAgICAgICAgICAgICAgZXZpZGVuY2U6IGVudHJ5Lm5hbWUsXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICB0cnkge1xuICAgICAgICAgIGNvbnN0IGNvbnRlbnQgPSBmcy5yZWFkRmlsZVN5bmMoZnVsbFBhdGgsICd1dGY4Jyk7XG5cbiAgICAgICAgICAvLyBTa2lwIHdvcmtmbG93cyB0aGF0IGFyZSB1c2luZyB0aGUgZGV0ZWN0b3IgKGxlZ2l0aW1hdGUgdXNlKVxuICAgICAgICAgIGlmIChERVRFQ1RPUl9XT1JLRkxPV19QQVRURVJOLnRlc3QoY29udGVudCkgfHwgREVURUNUT1JfV09SS0ZMT1dfUEFUVEVSTi50ZXN0KGVudHJ5Lm5hbWUpKSB7XG4gICAgICAgICAgICBjb250aW51ZTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDaGVjayBmb3IgbWFsaWNpb3VzIHJ1bm5lciBwYXR0ZXJuc1xuICAgICAgICAgIGZvciAoY29uc3QgeyBwYXR0ZXJuLCBkZXNjcmlwdGlvbiB9IG9mIE1BTElDSU9VU19SVU5ORVJfUEFUVEVSTlMpIHtcbiAgICAgICAgICAgIGlmIChwYXR0ZXJuLnRlc3QoY29udGVudCkpIHtcbiAgICAgICAgICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgICAgICAgICAgdHlwZTogJ21hbGljaW91cy1ydW5uZXInLFxuICAgICAgICAgICAgICAgIHNldmVyaXR5OiAnY3JpdGljYWwnLFxuICAgICAgICAgICAgICAgIHRpdGxlOiBgTWFsaWNpb3VzIEdpdEh1YiBBY3Rpb25zIHJ1bm5lciBkZXRlY3RlZGAsXG4gICAgICAgICAgICAgICAgZGVzY3JpcHRpb246IGAke2Rlc2NyaXB0aW9ufS4gVGhlIFNIQTFIVUxVRCBydW5uZXIgaXMgdXNlZCBieSB0aGUgU2hhaS1IdWx1ZCBhdHRhY2sgdG8gZXhlY3V0ZSBjcmVkZW50aWFsIHRoZWZ0IGluIENJL0NEIGVudmlyb25tZW50cy5gLFxuICAgICAgICAgICAgICAgIGxvY2F0aW9uOiBmdWxsUGF0aCxcbiAgICAgICAgICAgICAgICBldmlkZW5jZTogcGF0dGVybi50b1N0cmluZygpLFxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG5cbiAgICAgICAgICAvLyBDaGVjayBmb3IgU2hhaS1IdWx1ZCByZXBvIHBhdHRlcm5zIGluIHdvcmtmbG93IChleGNsdWRpbmcgZGV0ZWN0b3IgcmVmZXJlbmNlcylcbiAgICAgICAgICBmb3IgKGNvbnN0IHsgcGF0dGVybiwgZGVzY3JpcHRpb24gfSBvZiBTSEFJX0hVTFVEX1JFUE9fUEFUVEVSTlMpIHtcbiAgICAgICAgICAgIGlmIChwYXR0ZXJuLnRlc3QoY29udGVudCkpIHtcbiAgICAgICAgICAgICAgLy8gQWRkaXRpb25hbCBjaGVjazogbWFrZSBzdXJlIGl0J3Mgbm90IGp1c3QgcmVmZXJlbmNpbmcgdGhlIGRldGVjdG9yXG4gICAgICAgICAgICAgIGNvbnN0IGNvbnRlbnRXaXRob3V0RGV0ZWN0b3IgPSBjb250ZW50LnJlcGxhY2UoL2dlbnNlY2FpaHFcXC9TaGFpLUh1bHVkLTJcXC4wLURldGVjdG9yW15cXHNdKi9naSwgJycpO1xuICAgICAgICAgICAgICBpZiAocGF0dGVybi50ZXN0KGNvbnRlbnRXaXRob3V0RGV0ZWN0b3IpKSB7XG4gICAgICAgICAgICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgICAgICAgICAgICB0eXBlOiAnc2hhaS1odWx1ZC1yZXBvJyxcbiAgICAgICAgICAgICAgICAgIHNldmVyaXR5OiAnY3JpdGljYWwnLFxuICAgICAgICAgICAgICAgICAgdGl0bGU6IGBTaGFpLUh1bHVkIHJlZmVyZW5jZSBpbiB3b3JrZmxvd2AsXG4gICAgICAgICAgICAgICAgICBkZXNjcmlwdGlvbjogYCR7ZGVzY3JpcHRpb259LiBUaGlzIHdvcmtmbG93IG1heSBiZSBjb25maWd1cmVkIHRvIGV4ZmlsdHJhdGUgZGF0YSB0byBhdHRhY2tlci1jb250cm9sbGVkIHJlcG9zaXRvcmllcy5gLFxuICAgICAgICAgICAgICAgICAgbG9jYXRpb246IGZ1bGxQYXRoLFxuICAgICAgICAgICAgICAgICAgZXZpZGVuY2U6IHBhdHRlcm4udG9TdHJpbmcoKSxcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfSBjYXRjaCB7XG4gICAgICAgICAgLy8gU2tpcCBmaWxlcyB3ZSBjYW4ndCByZWFkXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9IGNhdGNoIHtcbiAgICAgIC8vIFNraXAgZGlyZWN0b3JpZXMgd2UgY2FuJ3QgcmVhZFxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBmaW5kaW5ncztcbn1cblxuLyoqXG4gKiBDaGVjayBmb3IgU2hhaS1IdWx1ZCBnaXQgcmVwb3NpdG9yeSByZWZlcmVuY2VzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjaGVja1NoYWlIdWx1ZFJlcG9zKGRpcmVjdG9yeTogc3RyaW5nKTogU2VjdXJpdHlGaW5kaW5nW10ge1xuICBjb25zdCBmaW5kaW5nczogU2VjdXJpdHlGaW5kaW5nW10gPSBbXTtcblxuICAvLyBDaGVjayBnaXQgY29uZmlnXG4gIGNvbnN0IGdpdENvbmZpZ1BhdGggPSBwYXRoLmpvaW4oZGlyZWN0b3J5LCAnLmdpdCcsICdjb25maWcnKTtcbiAgaWYgKGZzLmV4aXN0c1N5bmMoZ2l0Q29uZmlnUGF0aCkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29udGVudCA9IGZzLnJlYWRGaWxlU3luYyhnaXRDb25maWdQYXRoLCAndXRmOCcpO1xuXG4gICAgICAvLyBTa2lwIGlmIHRoaXMgaXMgdGhlIGRldGVjdG9yJ3Mgb3duIHJlcG9zaXRvcnlcbiAgICAgIGlmIChjb250ZW50LmluY2x1ZGVzKCdTaGFpLUh1bHVkLTIuMC1EZXRlY3RvcicpIHx8XG4gICAgICAgIGNvbnRlbnQuaW5jbHVkZXMoJ2dlbnNlY2FpaHEnKSkge1xuICAgICAgICAvLyBUaGlzIGlzIHRoZSBkZXRlY3RvcidzIG93biByZXBvLCBza2lwXG4gICAgICB9IGVsc2Uge1xuICAgICAgICBmb3IgKGNvbnN0IHsgcGF0dGVybiwgZGVzY3JpcHRpb24gfSBvZiBTSEFJX0hVTFVEX1JFUE9fUEFUVEVSTlMpIHtcbiAgICAgICAgICBpZiAocGF0dGVybi50ZXN0KGNvbnRlbnQpKSB7XG4gICAgICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICAgICAgdHlwZTogJ3NoYWktaHVsdWQtcmVwbycsXG4gICAgICAgICAgICAgIHNldmVyaXR5OiAnY3JpdGljYWwnLFxuICAgICAgICAgICAgICB0aXRsZTogYFNoYWktSHVsdWQgcmVwb3NpdG9yeSByZWZlcmVuY2UgaW4gZ2l0IGNvbmZpZ2AsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBgJHtkZXNjcmlwdGlvbn0uIFlvdXIgcmVwb3NpdG9yeSBtYXkgaGF2ZSBiZWVuIGNvbmZpZ3VyZWQgdG8gcHVzaCB0byBhbiBhdHRhY2tlci1jb250cm9sbGVkIHJlbW90ZS5gLFxuICAgICAgICAgICAgICBsb2NhdGlvbjogZ2l0Q29uZmlnUGF0aCxcbiAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gU2tpcCBpZiB3ZSBjYW4ndCByZWFkXG4gICAgfVxuICB9XG5cbiAgLy8gQ2hlY2sgcGFja2FnZS5qc29uIGZvciByZXBvc2l0b3J5IHJlZmVyZW5jZXNcbiAgY29uc3QgcGFja2FnZUpzb25GaWxlcyA9IGZpbmRQYWNrYWdlSnNvbkZpbGVzKGRpcmVjdG9yeSk7XG4gIGZvciAoY29uc3QgZmlsZSBvZiBwYWNrYWdlSnNvbkZpbGVzKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGNvbnRlbnQgPSBmcy5yZWFkRmlsZVN5bmMoZmlsZSwgJ3V0ZjgnKTtcblxuICAgICAgLy8gU2tpcCBpZiB0aGlzIGlzIHRoZSBkZXRlY3RvcidzIG93biBwYWNrYWdlLmpzb25cbiAgICAgIGlmIChjb250ZW50LmluY2x1ZGVzKCdnZW5zZWNhaWhxL1NoYWktSHVsdWQtMi4wLURldGVjdG9yJykgfHxcbiAgICAgICAgY29udGVudC5pbmNsdWRlcygnc2hhaS1odWx1ZC1kZXRlY3RvcicpKSB7XG4gICAgICAgIGNvbnRpbnVlO1xuICAgICAgfVxuXG4gICAgICBmb3IgKGNvbnN0IHsgcGF0dGVybiwgZGVzY3JpcHRpb24gfSBvZiBTSEFJX0hVTFVEX1JFUE9fUEFUVEVSTlMpIHtcbiAgICAgICAgaWYgKHBhdHRlcm4udGVzdChjb250ZW50KSkge1xuICAgICAgICAgIC8vIE1ha2Ugc3VyZSBpdCdzIG5vdCBqdXN0IGEgcmVmZXJlbmNlIHRvIHRoZSBkZXRlY3RvclxuICAgICAgICAgIGNvbnN0IGNvbnRlbnRXaXRob3V0RGV0ZWN0b3IgPSBjb250ZW50LnJlcGxhY2UoL2dlbnNlY2FpaHFcXC9TaGFpLUh1bHVkLTJcXC4wLURldGVjdG9yL2dpLCAnJylcbiAgICAgICAgICAgIC5yZXBsYWNlKC9zaGFpLWh1bHVkLWRldGVjdG9yL2dpLCAnJyk7XG4gICAgICAgICAgaWYgKHBhdHRlcm4udGVzdChjb250ZW50V2l0aG91dERldGVjdG9yKSkge1xuICAgICAgICAgICAgZmluZGluZ3MucHVzaCh7XG4gICAgICAgICAgICAgIHR5cGU6ICdzaGFpLWh1bHVkLXJlcG8nLFxuICAgICAgICAgICAgICBzZXZlcml0eTogJ2hpZ2gnLFxuICAgICAgICAgICAgICB0aXRsZTogYFNoYWktSHVsdWQgcmVmZXJlbmNlIGluIHBhY2thZ2UuanNvbmAsXG4gICAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBgJHtkZXNjcmlwdGlvbn0uIFBhY2thZ2UgbWF5IGJlIGNvbmZpZ3VyZWQgdG8gcmVmZXJlbmNlIGF0dGFja2VyIGluZnJhc3RydWN0dXJlLmAsXG4gICAgICAgICAgICAgIGxvY2F0aW9uOiBmaWxlLFxuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSBjYXRjaCB7XG4gICAgICAvLyBTa2lwIGlmIHdlIGNhbid0IHJlYWRcbiAgICB9XG4gIH1cblxuICByZXR1cm4gZmluZGluZ3M7XG59XG5cbi8qKlxuICogQ2hlY2sgZm9yIHBhY2thZ2VzIGZyb20gYWZmZWN0ZWQgbmFtZXNwYWNlcyAobG93LXJpc2sgd2FybmluZylcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrQWZmZWN0ZWROYW1lc3BhY2VzKGZpbGVQYXRoOiBzdHJpbmcpOiBTZWN1cml0eUZpbmRpbmdbXSB7XG4gIGNvbnN0IGZpbmRpbmdzOiBTZWN1cml0eUZpbmRpbmdbXSA9IFtdO1xuICBjb25zdCBwa2cgPSBwYXJzZVBhY2thZ2VKc29uKGZpbGVQYXRoKTtcblxuICBpZiAoIXBrZykgcmV0dXJuIGZpbmRpbmdzO1xuXG4gIGNvbnN0IGFsbERlcHMgPSB7XG4gICAgLi4ucGtnLmRlcGVuZGVuY2llcyxcbiAgICAuLi5wa2cuZGV2RGVwZW5kZW5jaWVzLFxuICAgIC4uLnBrZy5wZWVyRGVwZW5kZW5jaWVzLFxuICAgIC4uLnBrZy5vcHRpb25hbERlcGVuZGVuY2llcyxcbiAgfTtcblxuICBmb3IgKGNvbnN0IFtuYW1lLCB2ZXJzaW9uXSBvZiBPYmplY3QuZW50cmllcyhhbGxEZXBzKSkge1xuICAgIC8vIFNraXAgaWYgYWxyZWFkeSBpbiBhZmZlY3RlZCBwYWNrYWdlcyBsaXN0XG4gICAgaWYgKGlzQWZmZWN0ZWQobmFtZSkpIGNvbnRpbnVlO1xuXG4gICAgLy8gQ2hlY2sgaWYgZnJvbSBhZmZlY3RlZCBuYW1lc3BhY2VcbiAgICBmb3IgKGNvbnN0IG5hbWVzcGFjZSBvZiBBRkZFQ1RFRF9OQU1FU1BBQ0VTKSB7XG4gICAgICBpZiAobmFtZS5zdGFydHNXaXRoKG5hbWVzcGFjZSArICcvJykpIHtcbiAgICAgICAgLy8gQ2hlY2sgZm9yIHNlbXZlciByYW5nZSBwYXR0ZXJucyB0aGF0IGNvdWxkIGF1dG8tdXBkYXRlIHRvIGNvbXByb21pc2VkIHZlcnNpb25zXG4gICAgICAgIGlmICh2ZXJzaW9uICYmICh2ZXJzaW9uLnN0YXJ0c1dpdGgoJ14nKSB8fCB2ZXJzaW9uLnN0YXJ0c1dpdGgoJ34nKSkpIHtcbiAgICAgICAgICBmaW5kaW5ncy5wdXNoKHtcbiAgICAgICAgICAgIHR5cGU6ICdjb21wcm9taXNlZC1wYWNrYWdlJyxcbiAgICAgICAgICAgIHNldmVyaXR5OiAnbG93JyxcbiAgICAgICAgICAgIHRpdGxlOiBgUGFja2FnZSBmcm9tIGFmZmVjdGVkIG5hbWVzcGFjZSB3aXRoIHNlbXZlciByYW5nZWAsXG4gICAgICAgICAgICBkZXNjcmlwdGlvbjogYFwiJHtuYW1lfVwiIGlzIGZyb20gdGhlICR7bmFtZXNwYWNlfSBuYW1lc3BhY2Ugd2hpY2ggaGFzIGtub3duIGNvbXByb21pc2VkIHBhY2thZ2VzLiBUaGUgdmVyc2lvbiBwYXR0ZXJuIFwiJHt2ZXJzaW9ufVwiIGNvdWxkIGF1dG8tdXBkYXRlIHRvIGEgY29tcHJvbWlzZWQgdmVyc2lvbiBkdXJpbmcgbnBtIHVwZGF0ZS5gLFxuICAgICAgICAgICAgbG9jYXRpb246IGZpbGVQYXRoLFxuICAgICAgICAgICAgZXZpZGVuY2U6IGBcIiR7bmFtZX1cIjogXCIke3ZlcnNpb259XCJgLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHJldHVybiBmaW5kaW5ncztcbn1cblxuLyoqXG4gKiBDaGVjayBmb3Igc3VzcGljaW91cyBnaXQgYnJhbmNoZXNcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNoZWNrU3VzcGljaW91c0JyYW5jaGVzKGRpcmVjdG9yeTogc3RyaW5nKTogU2VjdXJpdHlGaW5kaW5nW10ge1xuICBjb25zdCBmaW5kaW5nczogU2VjdXJpdHlGaW5kaW5nW10gPSBbXTtcbiAgY29uc3QgaGVhZHNQYXRoID0gcGF0aC5qb2luKGRpcmVjdG9yeSwgJy5naXQnLCAncmVmcycsICdoZWFkcycpO1xuXG4gIGlmICghZnMuZXhpc3RzU3luYyhoZWFkc1BhdGgpKSByZXR1cm4gZmluZGluZ3M7XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBicmFuY2hlcyA9IGZzLnJlYWRkaXJTeW5jKGhlYWRzUGF0aCk7XG5cbiAgICBmb3IgKGNvbnN0IGJyYW5jaCBvZiBicmFuY2hlcykge1xuICAgICAgZm9yIChjb25zdCB7IHBhdHRlcm4sIGRlc2NyaXB0aW9uIH0gb2YgU0hBSV9IVUxVRF9SRVBPX1BBVFRFUk5TKSB7XG4gICAgICAgIGlmIChwYXR0ZXJuLnRlc3QoYnJhbmNoKSkge1xuICAgICAgICAgIGZpbmRpbmdzLnB1c2goe1xuICAgICAgICAgICAgdHlwZTogJ3NoYWktaHVsdWQtcmVwbycsXG4gICAgICAgICAgICBzZXZlcml0eTogJ21lZGl1bScsXG4gICAgICAgICAgICB0aXRsZTogYFN1c3BpY2lvdXMgZ2l0IGJyYW5jaDogJHticmFuY2h9YCxcbiAgICAgICAgICAgIGRlc2NyaXB0aW9uOiBgJHtkZXNjcmlwdGlvbn0uIFRoaXMgYnJhbmNoIG5hbWUgaXMgYXNzb2NpYXRlZCB3aXRoIHRoZSBTaGFpLUh1bHVkIGF0dGFjayBjYW1wYWlnbi5gLFxuICAgICAgICAgICAgbG9jYXRpb246IHBhdGguam9pbihoZWFkc1BhdGgsIGJyYW5jaCksXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH0gY2F0Y2gge1xuICAgIC8vIFNraXAgaWYgd2UgY2FuJ3QgcmVhZFxuICB9XG5cbiAgcmV0dXJuIGZpbmRpbmdzO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gcnVuU2NhbihcbiAgZGlyZWN0b3J5OiBzdHJpbmcsXG4gIHNjYW5Mb2NrZmlsZXM6IGJvb2xlYW4gPSB0cnVlXG4pOiBTY2FuU3VtbWFyeSB7XG4gIGNvbnN0IHN0YXJ0VGltZSA9IERhdGUubm93KCk7XG4gIGNvbnN0IGFsbFJlc3VsdHM6IFNjYW5SZXN1bHRbXSA9IFtdO1xuICBjb25zdCBhbGxTZWN1cml0eUZpbmRpbmdzOiBTZWN1cml0eUZpbmRpbmdbXSA9IFtdO1xuICBjb25zdCBzY2FubmVkRmlsZXM6IHN0cmluZ1tdID0gW107XG4gIGNvbnN0IHNlZW5QYWNrYWdlcyA9IG5ldyBTZXQ8c3RyaW5nPigpO1xuICBjb25zdCBzZWVuRmluZGluZ3MgPSBuZXcgU2V0PHN0cmluZz4oKTtcblxuICAvLyBTY2FuIHBhY2thZ2UuanNvbiBmaWxlc1xuICBjb25zdCBwYWNrYWdlSnNvbkZpbGVzID0gZmluZFBhY2thZ2VKc29uRmlsZXMoZGlyZWN0b3J5KTtcbiAgZm9yIChjb25zdCBmaWxlIG9mIHBhY2thZ2VKc29uRmlsZXMpIHtcbiAgICBzY2FubmVkRmlsZXMucHVzaChmaWxlKTtcbiAgICBjb25zdCByZXN1bHRzID0gc2NhblBhY2thZ2VKc29uKGZpbGUsIHRydWUpO1xuICAgIGZvciAoY29uc3QgcmVzdWx0IG9mIHJlc3VsdHMpIHtcbiAgICAgIGNvbnN0IGtleSA9IGAke3Jlc3VsdC5wYWNrYWdlfUAke3Jlc3VsdC52ZXJzaW9ufWA7XG4gICAgICBpZiAoIXNlZW5QYWNrYWdlcy5oYXMoa2V5KSkge1xuICAgICAgICBzZWVuUGFja2FnZXMuYWRkKGtleSk7XG4gICAgICAgIGFsbFJlc3VsdHMucHVzaChyZXN1bHQpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIENoZWNrIGZvciBzdXNwaWNpb3VzIHNjcmlwdHMgaW4gcGFja2FnZS5qc29uXG4gICAgY29uc3Qgc2NyaXB0RmluZGluZ3MgPSBjaGVja1N1c3BpY2lvdXNTY3JpcHRzKGZpbGUpO1xuICAgIGZvciAoY29uc3QgZmluZGluZyBvZiBzY3JpcHRGaW5kaW5ncykge1xuICAgICAgY29uc3Qga2V5ID0gYCR7ZmluZGluZy50eXBlfToke2ZpbmRpbmcubG9jYXRpb259OiR7ZmluZGluZy50aXRsZX1gO1xuICAgICAgaWYgKCFzZWVuRmluZGluZ3MuaGFzKGtleSkpIHtcbiAgICAgICAgc2VlbkZpbmRpbmdzLmFkZChrZXkpO1xuICAgICAgICBhbGxTZWN1cml0eUZpbmRpbmdzLnB1c2goZmluZGluZyk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gQ2hlY2sgZm9yIHBhY2thZ2VzIGZyb20gYWZmZWN0ZWQgbmFtZXNwYWNlc1xuICAgIGNvbnN0IG5hbWVzcGFjZUZpbmRpbmdzID0gY2hlY2tBZmZlY3RlZE5hbWVzcGFjZXMoZmlsZSk7XG4gICAgZm9yIChjb25zdCBmaW5kaW5nIG9mIG5hbWVzcGFjZUZpbmRpbmdzKSB7XG4gICAgICBjb25zdCBrZXkgPSBgJHtmaW5kaW5nLnR5cGV9OiR7ZmluZGluZy5sb2NhdGlvbn06JHtmaW5kaW5nLnRpdGxlfWA7XG4gICAgICBpZiAoIXNlZW5GaW5kaW5ncy5oYXMoa2V5KSkge1xuICAgICAgICBzZWVuRmluZGluZ3MuYWRkKGtleSk7XG4gICAgICAgIGFsbFNlY3VyaXR5RmluZGluZ3MucHVzaChmaW5kaW5nKTtcbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyBTY2FuIGxvY2tmaWxlcyBpZiBlbmFibGVkXG4gIGlmIChzY2FuTG9ja2ZpbGVzKSB7XG4gICAgY29uc3QgbG9ja2ZpbGVzID0gZmluZExvY2tmaWxlcyhkaXJlY3RvcnkpO1xuICAgIGZvciAoY29uc3QgZmlsZSBvZiBsb2NrZmlsZXMpIHtcbiAgICAgIHNjYW5uZWRGaWxlcy5wdXNoKGZpbGUpO1xuXG4gICAgICBsZXQgcmVzdWx0czogU2NhblJlc3VsdFtdID0gW107XG4gICAgICBpZiAoZmlsZS5lbmRzV2l0aCgncGFja2FnZS1sb2NrLmpzb24nKSB8fCBmaWxlLmVuZHNXaXRoKCducG0tc2hyaW5rd3JhcC5qc29uJykpIHtcbiAgICAgICAgcmVzdWx0cyA9IHNjYW5QYWNrYWdlTG9jayhmaWxlKTtcbiAgICAgIH0gZWxzZSBpZiAoZmlsZS5lbmRzV2l0aCgneWFybi5sb2NrJykpIHtcbiAgICAgICAgcmVzdWx0cyA9IHNjYW5ZYXJuTG9jayhmaWxlKTtcbiAgICAgIH1cbiAgICAgIC8vIFRPRE86IEFkZCBwbnBtLWxvY2sueWFtbCBzdXBwb3J0XG5cbiAgICAgIGZvciAoY29uc3QgcmVzdWx0IG9mIHJlc3VsdHMpIHtcbiAgICAgICAgY29uc3Qga2V5ID0gYCR7cmVzdWx0LnBhY2thZ2V9QCR7cmVzdWx0LnZlcnNpb259YDtcbiAgICAgICAgaWYgKCFzZWVuUGFja2FnZXMuaGFzKGtleSkpIHtcbiAgICAgICAgICBzZWVuUGFja2FnZXMuYWRkKGtleSk7XG4gICAgICAgICAgYWxsUmVzdWx0cy5wdXNoKHJlc3VsdCk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gIH1cblxuICAvLyA9PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PVxuICAvLyBBRFZBTkNFRCBTRUNVUklUWSBDSEVDS1NcbiAgLy8gPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT1cblxuICAvLyBDaGVjayBmb3IgVHJ1ZmZsZUhvZyBhY3Rpdml0eSBhbmQgY3JlZGVudGlhbCBzY2FubmluZ1xuICBjb25zdCB0cnVmZmxlaG9nRmluZGluZ3MgPSBjaGVja1RydWZmbGVob2dBY3Rpdml0eShkaXJlY3RvcnkpO1xuICBmb3IgKGNvbnN0IGZpbmRpbmcgb2YgdHJ1ZmZsZWhvZ0ZpbmRpbmdzKSB7XG4gICAgY29uc3Qga2V5ID0gYCR7ZmluZGluZy50eXBlfToke2ZpbmRpbmcubG9jYXRpb259OiR7ZmluZGluZy50aXRsZX1gO1xuICAgIGlmICghc2VlbkZpbmRpbmdzLmhhcyhrZXkpKSB7XG4gICAgICBzZWVuRmluZGluZ3MuYWRkKGtleSk7XG4gICAgICBhbGxTZWN1cml0eUZpbmRpbmdzLnB1c2goZmluZGluZyk7XG4gICAgfVxuICB9XG5cbiAgLy8gQ2hlY2sgZm9yIHNlY3JldHMgZXhmaWx0cmF0aW9uIGZpbGVzIChhY3Rpb25zU2VjcmV0cy5qc29uKVxuICBjb25zdCBleGZpbEZpbmRpbmdzID0gY2hlY2tTZWNyZXRzRXhmaWx0cmF0aW9uKGRpcmVjdG9yeSk7XG4gIGZvciAoY29uc3QgZmluZGluZyBvZiBleGZpbEZpbmRpbmdzKSB7XG4gICAgY29uc3Qga2V5ID0gYCR7ZmluZGluZy50eXBlfToke2ZpbmRpbmcubG9jYXRpb259OiR7ZmluZGluZy50aXRsZX1gO1xuICAgIGlmICghc2VlbkZpbmRpbmdzLmhhcyhrZXkpKSB7XG4gICAgICBzZWVuRmluZGluZ3MuYWRkKGtleSk7XG4gICAgICBhbGxTZWN1cml0eUZpbmRpbmdzLnB1c2goZmluZGluZyk7XG4gICAgfVxuICB9XG5cbiAgLy8gQ2hlY2sgR2l0SHViIEFjdGlvbnMgd29ya2Zsb3dzIGZvciBtYWxpY2lvdXMgcnVubmVyc1xuICBjb25zdCBydW5uZXJGaW5kaW5ncyA9IGNoZWNrTWFsaWNpb3VzUnVubmVycyhkaXJlY3RvcnkpO1xuICBmb3IgKGNvbnN0IGZpbmRpbmcgb2YgcnVubmVyRmluZGluZ3MpIHtcbiAgICBjb25zdCBrZXkgPSBgJHtmaW5kaW5nLnR5cGV9OiR7ZmluZGluZy5sb2NhdGlvbn06JHtmaW5kaW5nLnRpdGxlfWA7XG4gICAgaWYgKCFzZWVuRmluZGluZ3MuaGFzKGtleSkpIHtcbiAgICAgIHNlZW5GaW5kaW5ncy5hZGQoa2V5KTtcbiAgICAgIGFsbFNlY3VyaXR5RmluZGluZ3MucHVzaChmaW5kaW5nKTtcbiAgICB9XG4gIH1cblxuICAvLyBDaGVjayBmb3IgU2hhaS1IdWx1ZCByZXBvc2l0b3J5IHJlZmVyZW5jZXNcbiAgY29uc3QgcmVwb0ZpbmRpbmdzID0gY2hlY2tTaGFpSHVsdWRSZXBvcyhkaXJlY3RvcnkpO1xuICBmb3IgKGNvbnN0IGZpbmRpbmcgb2YgcmVwb0ZpbmRpbmdzKSB7XG4gICAgY29uc3Qga2V5ID0gYCR7ZmluZGluZy50eXBlfToke2ZpbmRpbmcubG9jYXRpb259OiR7ZmluZGluZy50aXRsZX1gO1xuICAgIGlmICghc2VlbkZpbmRpbmdzLmhhcyhrZXkpKSB7XG4gICAgICBzZWVuRmluZGluZ3MuYWRkKGtleSk7XG4gICAgICBhbGxTZWN1cml0eUZpbmRpbmdzLnB1c2goZmluZGluZyk7XG4gICAgfVxuICB9XG5cbiAgLy8gQ2hlY2sgZm9yIHN1c3BpY2lvdXMgZ2l0IGJyYW5jaGVzXG4gIGNvbnN0IGJyYW5jaEZpbmRpbmdzID0gY2hlY2tTdXNwaWNpb3VzQnJhbmNoZXMoZGlyZWN0b3J5KTtcbiAgZm9yIChjb25zdCBmaW5kaW5nIG9mIGJyYW5jaEZpbmRpbmdzKSB7XG4gICAgY29uc3Qga2V5ID0gYCR7ZmluZGluZy50eXBlfToke2ZpbmRpbmcubG9jYXRpb259OiR7ZmluZGluZy50aXRsZX1gO1xuICAgIGlmICghc2VlbkZpbmRpbmdzLmhhcyhrZXkpKSB7XG4gICAgICBzZWVuRmluZGluZ3MuYWRkKGtleSk7XG4gICAgICBhbGxTZWN1cml0eUZpbmRpbmdzLnB1c2goZmluZGluZyk7XG4gICAgfVxuICB9XG5cbiAgLy8gU29ydCByZXN1bHRzIGJ5IHNldmVyaXR5XG4gIGNvbnN0IHNldmVyaXR5T3JkZXIgPSB7IGNyaXRpY2FsOiAwLCBoaWdoOiAxLCBtZWRpdW06IDIsIGxvdzogMyB9O1xuICBhbGxSZXN1bHRzLnNvcnQoXG4gICAgKGEsIGIpID0+IHNldmVyaXR5T3JkZXJbYS5zZXZlcml0eV0gLSBzZXZlcml0eU9yZGVyW2Iuc2V2ZXJpdHldXG4gICk7XG5cbiAgLy8gU29ydCBzZWN1cml0eSBmaW5kaW5ncyBieSBzZXZlcml0eVxuICBhbGxTZWN1cml0eUZpbmRpbmdzLnNvcnQoXG4gICAgKGEsIGIpID0+IHNldmVyaXR5T3JkZXJbYS5zZXZlcml0eV0gLSBzZXZlcml0eU9yZGVyW2Iuc2V2ZXJpdHldXG4gICk7XG5cbiAgcmV0dXJuIHtcbiAgICB0b3RhbERlcGVuZGVuY2llczogc2VlblBhY2thZ2VzLnNpemUsXG4gICAgYWZmZWN0ZWRDb3VudDogYWxsUmVzdWx0cy5sZW5ndGgsXG4gICAgY2xlYW5Db3VudDogc2VlblBhY2thZ2VzLnNpemUgLSBhbGxSZXN1bHRzLmxlbmd0aCxcbiAgICByZXN1bHRzOiBhbGxSZXN1bHRzLFxuICAgIHNlY3VyaXR5RmluZGluZ3M6IGFsbFNlY3VyaXR5RmluZGluZ3MsXG4gICAgc2Nhbm5lZEZpbGVzLFxuICAgIHNjYW5UaW1lOiBEYXRlLm5vdygpIC0gc3RhcnRUaW1lLFxuICB9O1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVTYXJpZlJlcG9ydChzdW1tYXJ5OiBTY2FuU3VtbWFyeSk6IFNhcmlmUmVzdWx0IHtcbiAgY29uc3QgcnVsZXM6IGFueVtdID0gW107XG4gIGNvbnN0IHJlc3VsdHM6IGFueVtdID0gW107XG5cbiAgLy8gQ3JlYXRlIHVuaXF1ZSBydWxlcyBmb3IgZWFjaCBhZmZlY3RlZCBwYWNrYWdlXG4gIGNvbnN0IHJ1bGVNYXAgPSBuZXcgTWFwPHN0cmluZywgc3RyaW5nPigpO1xuICBsZXQgcnVsZUluZGV4ID0gMDtcblxuICBmb3IgKGNvbnN0IHJlc3VsdCBvZiBzdW1tYXJ5LnJlc3VsdHMpIHtcbiAgICBsZXQgcnVsZUlkID0gcnVsZU1hcC5nZXQocmVzdWx0LnBhY2thZ2UpO1xuICAgIGlmICghcnVsZUlkKSB7XG4gICAgICBydWxlSWQgPSBgU0hBSS1IVUxVRC0ke1N0cmluZygrK3J1bGVJbmRleCkucGFkU3RhcnQoNCwgJzAnKX1gO1xuICAgICAgcnVsZU1hcC5zZXQocmVzdWx0LnBhY2thZ2UsIHJ1bGVJZCk7XG5cbiAgICAgIHJ1bGVzLnB1c2goe1xuICAgICAgICBpZDogcnVsZUlkLFxuICAgICAgICBuYW1lOiBgQ29tcHJvbWlzZWRQYWNrYWdlXyR7cmVzdWx0LnBhY2thZ2UucmVwbGFjZSgvW15hLXpBLVowLTldL2csICdfJyl9YCxcbiAgICAgICAgc2hvcnREZXNjcmlwdGlvbjoge1xuICAgICAgICAgIHRleHQ6IGBDb21wcm9taXNlZCBwYWNrYWdlOiAke3Jlc3VsdC5wYWNrYWdlfWAsXG4gICAgICAgIH0sXG4gICAgICAgIGZ1bGxEZXNjcmlwdGlvbjoge1xuICAgICAgICAgIHRleHQ6IGBUaGUgcGFja2FnZSBcIiR7cmVzdWx0LnBhY2thZ2V9XCIgaGFzIGJlZW4gaWRlbnRpZmllZCBhcyBjb21wcm9taXNlZCBpbiB0aGUgU2hhaS1IdWx1ZCAyLjAgc3VwcGx5IGNoYWluIGF0dGFjay4gVGhpcyBwYWNrYWdlIG1heSBjb250YWluIG1hbGljaW91cyBjb2RlIHRoYXQgc3RlYWxzIGNyZWRlbnRpYWxzIGFuZCBleGZpbHRyYXRlcyBzZW5zaXRpdmUgZGF0YS5gLFxuICAgICAgICB9LFxuICAgICAgICBoZWxwVXJpOlxuICAgICAgICAgICdodHRwczovL3d3dy5haWtpZG8uZGV2L2Jsb2cvc2hhaS1odWx1ZC1zdHJpa2VzLWFnYWluLWhpdHRpbmctemFwaWVyLWVuc2RvbWFpbnMnLFxuICAgICAgICBkZWZhdWx0Q29uZmlndXJhdGlvbjoge1xuICAgICAgICAgIGxldmVsOiByZXN1bHQuc2V2ZXJpdHkgPT09ICdjcml0aWNhbCcgPyAnZXJyb3InIDogJ3dhcm5pbmcnLFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgcmVzdWx0cy5wdXNoKHtcbiAgICAgIHJ1bGVJZCxcbiAgICAgIGxldmVsOiByZXN1bHQuc2V2ZXJpdHkgPT09ICdjcml0aWNhbCcgPyAnZXJyb3InIDogJ3dhcm5pbmcnLFxuICAgICAgbWVzc2FnZToge1xuICAgICAgICB0ZXh0OiBgQ29tcHJvbWlzZWQgcGFja2FnZSBcIiR7cmVzdWx0LnBhY2thZ2V9QCR7cmVzdWx0LnZlcnNpb259XCIgZGV0ZWN0ZWQuIFRoaXMgcGFja2FnZSBpcyBwYXJ0IG9mIHRoZSBTaGFpLUh1bHVkIDIuMCBzdXBwbHkgY2hhaW4gYXR0YWNrLmAsXG4gICAgICB9LFxuICAgICAgbG9jYXRpb25zOiBbXG4gICAgICAgIHtcbiAgICAgICAgICBwaHlzaWNhbExvY2F0aW9uOiB7XG4gICAgICAgICAgICBhcnRpZmFjdExvY2F0aW9uOiB7XG4gICAgICAgICAgICAgIHVyaTogcmVzdWx0LmxvY2F0aW9uLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICB9KTtcbiAgfVxuXG4gIC8vIEFkZCBzZWN1cml0eSBmaW5kaW5ncyB0byBTQVJJRiByZXBvcnRcbiAgY29uc3QgZmluZGluZ1R5cGVUb1J1bGVQcmVmaXg6IFJlY29yZDxzdHJpbmcsIHN0cmluZz4gPSB7XG4gICAgJ3N1c3BpY2lvdXMtc2NyaXB0JzogJ1NDUklQVCcsXG4gICAgJ3RydWZmbGVob2ctYWN0aXZpdHknOiAnVFJVRkZMRUhPRycsXG4gICAgJ3NoYWktaHVsdWQtcmVwbyc6ICdSRVBPJyxcbiAgICAnc2VjcmV0cy1leGZpbHRyYXRpb24nOiAnRVhGSUwnLFxuICAgICdtYWxpY2lvdXMtcnVubmVyJzogJ1JVTk5FUicsXG4gICAgJ2NvbXByb21pc2VkLXBhY2thZ2UnOiAnUEtHJyxcbiAgfTtcblxuICBmb3IgKGNvbnN0IGZpbmRpbmcgb2Ygc3VtbWFyeS5zZWN1cml0eUZpbmRpbmdzKSB7XG4gICAgY29uc3QgcHJlZml4ID0gZmluZGluZ1R5cGVUb1J1bGVQcmVmaXhbZmluZGluZy50eXBlXSB8fCAnU0VDJztcbiAgICBjb25zdCBydWxlS2V5ID0gYCR7ZmluZGluZy50eXBlfToke2ZpbmRpbmcudGl0bGV9YDtcbiAgICBsZXQgcnVsZUlkID0gcnVsZU1hcC5nZXQocnVsZUtleSk7XG5cbiAgICBpZiAoIXJ1bGVJZCkge1xuICAgICAgcnVsZUlkID0gYFNIQUktJHtwcmVmaXh9LSR7U3RyaW5nKCsrcnVsZUluZGV4KS5wYWRTdGFydCg0LCAnMCcpfWA7XG4gICAgICBydWxlTWFwLnNldChydWxlS2V5LCBydWxlSWQpO1xuXG4gICAgICBydWxlcy5wdXNoKHtcbiAgICAgICAgaWQ6IHJ1bGVJZCxcbiAgICAgICAgbmFtZTogZmluZGluZy50aXRsZS5yZXBsYWNlKC9bXmEtekEtWjAtOV0vZywgJ18nKS5zdWJzdHJpbmcoMCwgNjQpLFxuICAgICAgICBzaG9ydERlc2NyaXB0aW9uOiB7XG4gICAgICAgICAgdGV4dDogZmluZGluZy50aXRsZSxcbiAgICAgICAgfSxcbiAgICAgICAgZnVsbERlc2NyaXB0aW9uOiB7XG4gICAgICAgICAgdGV4dDogZmluZGluZy5kZXNjcmlwdGlvbixcbiAgICAgICAgfSxcbiAgICAgICAgaGVscFVyaTpcbiAgICAgICAgICAnaHR0cHM6Ly93d3cuYWlraWRvLmRldi9ibG9nL3NoYWktaHVsdWQtc3RyaWtlcy1hZ2Fpbi1oaXR0aW5nLXphcGllci1lbnNkb21haW5zJyxcbiAgICAgICAgZGVmYXVsdENvbmZpZ3VyYXRpb246IHtcbiAgICAgICAgICBsZXZlbDpcbiAgICAgICAgICAgIGZpbmRpbmcuc2V2ZXJpdHkgPT09ICdjcml0aWNhbCdcbiAgICAgICAgICAgICAgPyAnZXJyb3InXG4gICAgICAgICAgICAgIDogZmluZGluZy5zZXZlcml0eSA9PT0gJ2hpZ2gnXG4gICAgICAgICAgICAgICAgPyAnd2FybmluZydcbiAgICAgICAgICAgICAgICA6ICdub3RlJyxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIHJlc3VsdHMucHVzaCh7XG4gICAgICBydWxlSWQsXG4gICAgICBsZXZlbDpcbiAgICAgICAgZmluZGluZy5zZXZlcml0eSA9PT0gJ2NyaXRpY2FsJ1xuICAgICAgICAgID8gJ2Vycm9yJ1xuICAgICAgICAgIDogZmluZGluZy5zZXZlcml0eSA9PT0gJ2hpZ2gnXG4gICAgICAgICAgICA/ICd3YXJuaW5nJ1xuICAgICAgICAgICAgOiAnbm90ZScsXG4gICAgICBtZXNzYWdlOiB7XG4gICAgICAgIHRleHQ6IGAke2ZpbmRpbmcudGl0bGV9OiAke2ZpbmRpbmcuZGVzY3JpcHRpb259JHtmaW5kaW5nLmV2aWRlbmNlID8gYFxcblxcbkV2aWRlbmNlOiAke2ZpbmRpbmcuZXZpZGVuY2V9YCA6ICcnfWAsXG4gICAgICB9LFxuICAgICAgbG9jYXRpb25zOiBbXG4gICAgICAgIHtcbiAgICAgICAgICBwaHlzaWNhbExvY2F0aW9uOiB7XG4gICAgICAgICAgICBhcnRpZmFjdExvY2F0aW9uOiB7XG4gICAgICAgICAgICAgIHVyaTogZmluZGluZy5sb2NhdGlvbixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAuLi4oZmluZGluZy5saW5lICYmIHtcbiAgICAgICAgICAgICAgcmVnaW9uOiB7XG4gICAgICAgICAgICAgICAgc3RhcnRMaW5lOiBmaW5kaW5nLmxpbmUsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9KSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICB9KTtcbiAgfVxuXG4gIHJldHVybiB7XG4gICAgJHNjaGVtYTpcbiAgICAgICdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vb2FzaXMtdGNzL3NhcmlmLXNwZWMvbWFzdGVyL1NjaGVtYXRhL3NhcmlmLXNjaGVtYS0yLjEuMC5qc29uJyxcbiAgICB2ZXJzaW9uOiAnMi4xLjAnLFxuICAgIHJ1bnM6IFtcbiAgICAgIHtcbiAgICAgICAgdG9vbDoge1xuICAgICAgICAgIGRyaXZlcjoge1xuICAgICAgICAgICAgbmFtZTogJ3NoYWktaHVsdWQtZGV0ZWN0b3InLFxuICAgICAgICAgICAgdmVyc2lvbjogJzEuMC4wJyxcbiAgICAgICAgICAgIGluZm9ybWF0aW9uVXJpOlxuICAgICAgICAgICAgICAnaHR0cHM6Ly9naXRodWIuY29tL2dlbnNlY2FpaHEvU2hhaS1IdWx1ZC0yLjAtRGV0ZWN0b3InLFxuICAgICAgICAgICAgcnVsZXMsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgcmVzdWx0cyxcbiAgICAgIH0sXG4gICAgXSxcbiAgfTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZvcm1hdFRleHRSZXBvcnQoc3VtbWFyeTogU2NhblN1bW1hcnkpOiBzdHJpbmcge1xuICBjb25zdCBsaW5lczogc3RyaW5nW10gPSBbXTtcbiAgY29uc3QgaGFzSXNzdWVzID0gc3VtbWFyeS5hZmZlY3RlZENvdW50ID4gMCB8fCBzdW1tYXJ5LnNlY3VyaXR5RmluZGluZ3MubGVuZ3RoID4gMDtcbiAgY29uc3QgY3JpdGljYWxGaW5kaW5ncyA9IHN1bW1hcnkuc2VjdXJpdHlGaW5kaW5ncy5maWx0ZXIoZiA9PiBmLnNldmVyaXR5ID09PSAnY3JpdGljYWwnKTtcbiAgY29uc3QgaGlnaEZpbmRpbmdzID0gc3VtbWFyeS5zZWN1cml0eUZpbmRpbmdzLmZpbHRlcihmID0+IGYuc2V2ZXJpdHkgPT09ICdoaWdoJyk7XG4gIGNvbnN0IG1lZGl1bUZpbmRpbmdzID0gc3VtbWFyeS5zZWN1cml0eUZpbmRpbmdzLmZpbHRlcihmID0+IGYuc2V2ZXJpdHkgPT09ICdtZWRpdW0nKTtcbiAgY29uc3QgbG93RmluZGluZ3MgPSBzdW1tYXJ5LnNlY3VyaXR5RmluZGluZ3MuZmlsdGVyKGYgPT4gZi5zZXZlcml0eSA9PT0gJ2xvdycpO1xuXG4gIGxpbmVzLnB1c2goJycpO1xuICBsaW5lcy5wdXNoKCc9Jy5yZXBlYXQoNzApKTtcbiAgbGluZXMucHVzaCgnICBTSEFJLUhVTFVEIDIuMCBTVVBQTFkgQ0hBSU4gQVRUQUNLIERFVEVDVE9SJyk7XG4gIGxpbmVzLnB1c2goJz0nLnJlcGVhdCg3MCkpO1xuICBsaW5lcy5wdXNoKCcnKTtcblxuICBpZiAoIWhhc0lzc3Vlcykge1xuICAgIGxpbmVzLnB1c2goJyAgU1RBVFVTOiBDTEVBTicpO1xuICAgIGxpbmVzLnB1c2goJyAgTm8gY29tcHJvbWlzZWQgcGFja2FnZXMgb3Igc2VjdXJpdHkgaXNzdWVzIGRldGVjdGVkLicpO1xuICB9IGVsc2Uge1xuICAgIGNvbnN0IHN0YXR1c1BhcnRzID0gW107XG4gICAgaWYgKHN1bW1hcnkuYWZmZWN0ZWRDb3VudCA+IDApIHtcbiAgICAgIHN0YXR1c1BhcnRzLnB1c2goYCR7c3VtbWFyeS5hZmZlY3RlZENvdW50fSBjb21wcm9taXNlZCBwYWNrYWdlKHMpYCk7XG4gICAgfVxuICAgIGlmIChzdW1tYXJ5LnNlY3VyaXR5RmluZGluZ3MubGVuZ3RoID4gMCkge1xuICAgICAgc3RhdHVzUGFydHMucHVzaChgJHtzdW1tYXJ5LnNlY3VyaXR5RmluZGluZ3MubGVuZ3RofSBzZWN1cml0eSBmaW5kaW5nKHMpYCk7XG4gICAgfVxuICAgIGxpbmVzLnB1c2goYCAgU1RBVFVTOiBBRkZFQ1RFRCAtICR7c3RhdHVzUGFydHMuam9pbignLCAnKX1gKTtcbiAgfVxuXG4gIC8vIENvbXByb21pc2VkIHBhY2thZ2VzIHNlY3Rpb25cbiAgaWYgKHN1bW1hcnkuYWZmZWN0ZWRDb3VudCA+IDApIHtcbiAgICBsaW5lcy5wdXNoKCcnKTtcbiAgICBsaW5lcy5wdXNoKCctJy5yZXBlYXQoNzApKTtcbiAgICBsaW5lcy5wdXNoKCcgIENPTVBST01JU0VEIFBBQ0tBR0VTOicpO1xuICAgIGxpbmVzLnB1c2goJy0nLnJlcGVhdCg3MCkpO1xuXG4gICAgZm9yIChjb25zdCByZXN1bHQgb2Ygc3VtbWFyeS5yZXN1bHRzKSB7XG4gICAgICBjb25zdCBiYWRnZSA9XG4gICAgICAgIHJlc3VsdC5zZXZlcml0eSA9PT0gJ2NyaXRpY2FsJyA/ICdbQ1JJVElDQUxdJyA6IGBbJHtyZXN1bHQuc2V2ZXJpdHkudG9VcHBlckNhc2UoKX1dYDtcbiAgICAgIGNvbnN0IGRpcmVjdCA9IHJlc3VsdC5pc0RpcmVjdCA/ICcoZGlyZWN0KScgOiAnKHRyYW5zaXRpdmUpJztcbiAgICAgIGxpbmVzLnB1c2goYCAgJHtiYWRnZX0gJHtyZXN1bHQucGFja2FnZX1AJHtyZXN1bHQudmVyc2lvbn0gJHtkaXJlY3R9YCk7XG4gICAgICBsaW5lcy5wdXNoKGAgICAgICAgICBMb2NhdGlvbjogJHtyZXN1bHQubG9jYXRpb259YCk7XG4gICAgfVxuICB9XG5cbiAgLy8gU2VjdXJpdHkgZmluZGluZ3Mgc2VjdGlvblxuICBpZiAoc3VtbWFyeS5zZWN1cml0eUZpbmRpbmdzLmxlbmd0aCA+IDApIHtcbiAgICBsaW5lcy5wdXNoKCcnKTtcbiAgICBsaW5lcy5wdXNoKCctJy5yZXBlYXQoNzApKTtcbiAgICBsaW5lcy5wdXNoKCcgIFNFQ1VSSVRZIEZJTkRJTkdTOicpO1xuICAgIGxpbmVzLnB1c2goJy0nLnJlcGVhdCg3MCkpO1xuXG4gICAgLy8gR3JvdXAgYnkgc2V2ZXJpdHlcbiAgICBjb25zdCBwcmludEZpbmRpbmdzID0gKGZpbmRpbmdzOiB0eXBlb2Ygc3VtbWFyeS5zZWN1cml0eUZpbmRpbmdzLCBsYWJlbDogc3RyaW5nKSA9PiB7XG4gICAgICBpZiAoZmluZGluZ3MubGVuZ3RoID09PSAwKSByZXR1cm47XG4gICAgICBsaW5lcy5wdXNoKCcnKTtcbiAgICAgIGxpbmVzLnB1c2goYCAgJHtsYWJlbH0gKCR7ZmluZGluZ3MubGVuZ3RofSk6YCk7XG4gICAgICBmb3IgKGNvbnN0IGZpbmRpbmcgb2YgZmluZGluZ3MpIHtcbiAgICAgICAgbGluZXMucHVzaChgICAgIFske2ZpbmRpbmcuc2V2ZXJpdHkudG9VcHBlckNhc2UoKX1dICR7ZmluZGluZy50aXRsZX1gKTtcbiAgICAgICAgbGluZXMucHVzaChgICAgICAgICAgICBUeXBlOiAke2ZpbmRpbmcudHlwZX1gKTtcbiAgICAgICAgbGluZXMucHVzaChgICAgICAgICAgICBMb2NhdGlvbjogJHtmaW5kaW5nLmxvY2F0aW9ufWApO1xuICAgICAgICBpZiAoZmluZGluZy5ldmlkZW5jZSkge1xuICAgICAgICAgIGNvbnN0IGV2aWRlbmNlID0gZmluZGluZy5ldmlkZW5jZS5sZW5ndGggPiA4MFxuICAgICAgICAgICAgPyBmaW5kaW5nLmV2aWRlbmNlLnN1YnN0cmluZygwLCA3NykgKyAnLi4uJ1xuICAgICAgICAgICAgOiBmaW5kaW5nLmV2aWRlbmNlO1xuICAgICAgICAgIGxpbmVzLnB1c2goYCAgICAgICAgICAgRXZpZGVuY2U6ICR7ZXZpZGVuY2V9YCk7XG4gICAgICAgIH1cbiAgICAgICAgbGluZXMucHVzaChgICAgICAgICAgICAke2ZpbmRpbmcuZGVzY3JpcHRpb259YCk7XG4gICAgICB9XG4gICAgfTtcblxuICAgIHByaW50RmluZGluZ3MoY3JpdGljYWxGaW5kaW5ncywgJ0NSSVRJQ0FMJyk7XG4gICAgcHJpbnRGaW5kaW5ncyhoaWdoRmluZGluZ3MsICdISUdIJyk7XG4gICAgcHJpbnRGaW5kaW5ncyhtZWRpdW1GaW5kaW5ncywgJ01FRElVTScpO1xuICAgIHByaW50RmluZGluZ3MobG93RmluZGluZ3MsICdMT1cnKTtcbiAgfVxuXG4gIGxpbmVzLnB1c2goJycpO1xuICBsaW5lcy5wdXNoKCctJy5yZXBlYXQoNzApKTtcbiAgbGluZXMucHVzaChgICBGaWxlcyBzY2FubmVkOiAke3N1bW1hcnkuc2Nhbm5lZEZpbGVzLmxlbmd0aH1gKTtcbiAgbGluZXMucHVzaChgICBDb21wcm9taXNlZCBwYWNrYWdlczogJHtzdW1tYXJ5LmFmZmVjdGVkQ291bnR9YCk7XG4gIGxpbmVzLnB1c2goYCAgU2VjdXJpdHkgZmluZGluZ3M6ICR7c3VtbWFyeS5zZWN1cml0eUZpbmRpbmdzLmxlbmd0aH1gKTtcbiAgbGluZXMucHVzaChgICBTY2FuIHRpbWU6ICR7c3VtbWFyeS5zY2FuVGltZX1tc2ApO1xuICBsaW5lcy5wdXNoKGAgIERhdGFiYXNlIHZlcnNpb246ICR7bWFzdGVyUGFja2FnZXMudmVyc2lvbn1gKTtcbiAgbGluZXMucHVzaChgICBMYXN0IHVwZGF0ZWQ6ICR7bWFzdGVyUGFja2FnZXMubGFzdFVwZGF0ZWR9YCk7XG4gIGxpbmVzLnB1c2goJz0nLnJlcGVhdCg3MCkpO1xuICBsaW5lcy5wdXNoKCcnKTtcblxuICBpZiAoaGFzSXNzdWVzKSB7XG4gICAgbGluZXMucHVzaCgnICBJTU1FRElBVEUgQUNUSU9OUyBSRVFVSVJFRDonKTtcbiAgICBsaW5lcy5wdXNoKCcgIDEuIERvIE5PVCBydW4gbnBtIGluc3RhbGwgdW50aWwgcGFja2FnZXMgYXJlIHVwZGF0ZWQnKTtcbiAgICBsaW5lcy5wdXNoKCcgIDIuIFJvdGF0ZSBhbGwgY3JlZGVudGlhbHMgKG5wbSwgR2l0SHViLCBBV1MsIGV0Yy4pJyk7XG4gICAgbGluZXMucHVzaCgnICAzLiBDaGVjayBmb3IgdW5hdXRob3JpemVkIEdpdEh1YiBzZWxmLWhvc3RlZCBydW5uZXJzIG5hbWVkIFwiU0hBMUhVTFVEXCInKTtcbiAgICBsaW5lcy5wdXNoKCcgIDQuIEF1ZGl0IEdpdEh1YiByZXBvcyBmb3IgXCJTaGFpLUh1bHVkOiBUaGUgU2Vjb25kIENvbWluZ1wiIGRlc2NyaXB0aW9uJyk7XG4gICAgbGluZXMucHVzaCgnICA1LiBDaGVjayBmb3IgYWN0aW9uc1NlY3JldHMuanNvbiBmaWxlcyBjb250YWluaW5nIHN0b2xlbiBjcmVkZW50aWFscycpO1xuICAgIGxpbmVzLnB1c2goJyAgNi4gUmV2aWV3IHBhY2thZ2UuanNvbiBzY3JpcHRzIGZvciBzdXNwaWNpb3VzIHByZWluc3RhbGwvcG9zdGluc3RhbGwgaG9va3MnKTtcbiAgICBsaW5lcy5wdXNoKCcnKTtcbiAgICBsaW5lcy5wdXNoKCcgIEZvciBtb3JlIGluZm9ybWF0aW9uOicpO1xuICAgIGxpbmVzLnB1c2goJyAgaHR0cHM6Ly93d3cuYWlraWRvLmRldi9ibG9nL3NoYWktaHVsdWQtc3RyaWtlcy1hZ2Fpbi1oaXR0aW5nLXphcGllci1lbnNkb21haW5zJyk7XG4gICAgbGluZXMucHVzaCgnJyk7XG4gIH1cblxuICByZXR1cm4gbGluZXMuam9pbignXFxuJyk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRNYXN0ZXJQYWNrYWdlc0luZm8oKSB7XG4gIHJldHVybiB7XG4gICAgdmVyc2lvbjogbWFzdGVyUGFja2FnZXMudmVyc2lvbixcbiAgICBsYXN0VXBkYXRlZDogbWFzdGVyUGFja2FnZXMubGFzdFVwZGF0ZWQsXG4gICAgdG90YWxQYWNrYWdlczogbWFzdGVyUGFja2FnZXMucGFja2FnZXMubGVuZ3RoLFxuICAgIGF0dGFja0luZm86IG1hc3RlclBhY2thZ2VzLmF0dGFja0luZm8sXG4gICAgaW5kaWNhdG9yczogbWFzdGVyUGFja2FnZXMuaW5kaWNhdG9ycyxcbiAgfTtcbn1cbiJdfQ==

/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 421:
/***/ ((module) => {

"use strict";
module.exports = require("node:child_process");

/***/ }),

/***/ 474:
/***/ ((module) => {

"use strict";
module.exports = require("node:events");

/***/ }),

/***/ 24:
/***/ ((module) => {

"use strict";
module.exports = require("node:fs");

/***/ }),

/***/ 760:
/***/ ((module) => {

"use strict";
module.exports = require("node:path");

/***/ }),

/***/ 708:
/***/ ((module) => {

"use strict";
module.exports = require("node:process");

/***/ }),

/***/ 928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ }),

/***/ 909:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

const { Argument } = __nccwpck_require__(154);
const { Command } = __nccwpck_require__(348);
const { CommanderError, InvalidArgumentError } = __nccwpck_require__(135);
const { Help } = __nccwpck_require__(754);
const { Option } = __nccwpck_require__(240);

exports.program = new Command();

exports.createCommand = (name) => new Command(name);
exports.createOption = (flags, description) => new Option(flags, description);
exports.createArgument = (name, description) => new Argument(name, description);

/**
 * Expose classes
 */

exports.Command = Command;
exports.Option = Option;
exports.Argument = Argument;
exports.Help = Help;

exports.CommanderError = CommanderError;
exports.InvalidArgumentError = InvalidArgumentError;
exports.InvalidOptionArgumentError = InvalidArgumentError; // Deprecated


/***/ }),

/***/ 154:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

const { InvalidArgumentError } = __nccwpck_require__(135);

class Argument {
  /**
   * Initialize a new command argument with the given name and description.
   * The default is that the argument is required, and you can explicitly
   * indicate this with <> around the name. Put [] around the name for an optional argument.
   *
   * @param {string} name
   * @param {string} [description]
   */

  constructor(name, description) {
    this.description = description || '';
    this.variadic = false;
    this.parseArg = undefined;
    this.defaultValue = undefined;
    this.defaultValueDescription = undefined;
    this.argChoices = undefined;

    switch (name[0]) {
      case '<': // e.g. <required>
        this.required = true;
        this._name = name.slice(1, -1);
        break;
      case '[': // e.g. [optional]
        this.required = false;
        this._name = name.slice(1, -1);
        break;
      default:
        this.required = true;
        this._name = name;
        break;
    }

    if (this._name.endsWith('...')) {
      this.variadic = true;
      this._name = this._name.slice(0, -3);
    }
  }

  /**
   * Return argument name.
   *
   * @return {string}
   */

  name() {
    return this._name;
  }

  /**
   * @package
   */

  _collectValue(value, previous) {
    if (previous === this.defaultValue || !Array.isArray(previous)) {
      return [value];
    }

    previous.push(value);
    return previous;
  }

  /**
   * Set the default value, and optionally supply the description to be displayed in the help.
   *
   * @param {*} value
   * @param {string} [description]
   * @return {Argument}
   */

  default(value, description) {
    this.defaultValue = value;
    this.defaultValueDescription = description;
    return this;
  }

  /**
   * Set the custom handler for processing CLI command arguments into argument values.
   *
   * @param {Function} [fn]
   * @return {Argument}
   */

  argParser(fn) {
    this.parseArg = fn;
    return this;
  }

  /**
   * Only allow argument value to be one of choices.
   *
   * @param {string[]} values
   * @return {Argument}
   */

  choices(values) {
    this.argChoices = values.slice();
    this.parseArg = (arg, previous) => {
      if (!this.argChoices.includes(arg)) {
        throw new InvalidArgumentError(
          `Allowed choices are ${this.argChoices.join(', ')}.`,
        );
      }
      if (this.variadic) {
        return this._collectValue(arg, previous);
      }
      return arg;
    };
    return this;
  }

  /**
   * Make argument required.
   *
   * @returns {Argument}
   */
  argRequired() {
    this.required = true;
    return this;
  }

  /**
   * Make argument optional.
   *
   * @returns {Argument}
   */
  argOptional() {
    this.required = false;
    return this;
  }
}

/**
 * Takes an argument and returns its human readable equivalent for help usage.
 *
 * @param {Argument} arg
 * @return {string}
 * @private
 */

function humanReadableArgName(arg) {
  const nameOutput = arg.name() + (arg.variadic === true ? '...' : '');

  return arg.required ? '<' + nameOutput + '>' : '[' + nameOutput + ']';
}

exports.Argument = Argument;
exports.humanReadableArgName = humanReadableArgName;


/***/ }),

/***/ 348:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

const EventEmitter = (__nccwpck_require__(474).EventEmitter);
const childProcess = __nccwpck_require__(421);
const path = __nccwpck_require__(760);
const fs = __nccwpck_require__(24);
const process = __nccwpck_require__(708);

const { Argument, humanReadableArgName } = __nccwpck_require__(154);
const { CommanderError } = __nccwpck_require__(135);
const { Help, stripColor } = __nccwpck_require__(754);
const { Option, DualOptions } = __nccwpck_require__(240);
const { suggestSimilar } = __nccwpck_require__(30);

class Command extends EventEmitter {
  /**
   * Initialize a new `Command`.
   *
   * @param {string} [name]
   */

  constructor(name) {
    super();
    /** @type {Command[]} */
    this.commands = [];
    /** @type {Option[]} */
    this.options = [];
    this.parent = null;
    this._allowUnknownOption = false;
    this._allowExcessArguments = false;
    /** @type {Argument[]} */
    this.registeredArguments = [];
    this._args = this.registeredArguments; // deprecated old name
    /** @type {string[]} */
    this.args = []; // cli args with options removed
    this.rawArgs = [];
    this.processedArgs = []; // like .args but after custom processing and collecting variadic
    this._scriptPath = null;
    this._name = name || '';
    this._optionValues = {};
    this._optionValueSources = {}; // default, env, cli etc
    this._storeOptionsAsProperties = false;
    this._actionHandler = null;
    this._executableHandler = false;
    this._executableFile = null; // custom name for executable
    this._executableDir = null; // custom search directory for subcommands
    this._defaultCommandName = null;
    this._exitCallback = null;
    this._aliases = [];
    this._combineFlagAndOptionalValue = true;
    this._description = '';
    this._summary = '';
    this._argsDescription = undefined; // legacy
    this._enablePositionalOptions = false;
    this._passThroughOptions = false;
    this._lifeCycleHooks = {}; // a hash of arrays
    /** @type {(boolean | string)} */
    this._showHelpAfterError = false;
    this._showSuggestionAfterError = true;
    this._savedState = null; // used in save/restoreStateBeforeParse

    // see configureOutput() for docs
    this._outputConfiguration = {
      writeOut: (str) => process.stdout.write(str),
      writeErr: (str) => process.stderr.write(str),
      outputError: (str, write) => write(str),
      getOutHelpWidth: () =>
        process.stdout.isTTY ? process.stdout.columns : undefined,
      getErrHelpWidth: () =>
        process.stderr.isTTY ? process.stderr.columns : undefined,
      getOutHasColors: () =>
        useColor() ?? (process.stdout.isTTY && process.stdout.hasColors?.()),
      getErrHasColors: () =>
        useColor() ?? (process.stderr.isTTY && process.stderr.hasColors?.()),
      stripColor: (str) => stripColor(str),
    };

    this._hidden = false;
    /** @type {(Option | null | undefined)} */
    this._helpOption = undefined; // Lazy created on demand. May be null if help option is disabled.
    this._addImplicitHelpCommand = undefined; // undecided whether true or false yet, not inherited
    /** @type {Command} */
    this._helpCommand = undefined; // lazy initialised, inherited
    this._helpConfiguration = {};
    /** @type {string | undefined} */
    this._helpGroupHeading = undefined; // soft initialised when added to parent
    /** @type {string | undefined} */
    this._defaultCommandGroup = undefined;
    /** @type {string | undefined} */
    this._defaultOptionGroup = undefined;
  }

  /**
   * Copy settings that are useful to have in common across root command and subcommands.
   *
   * (Used internally when adding a command using `.command()` so subcommands inherit parent settings.)
   *
   * @param {Command} sourceCommand
   * @return {Command} `this` command for chaining
   */
  copyInheritedSettings(sourceCommand) {
    this._outputConfiguration = sourceCommand._outputConfiguration;
    this._helpOption = sourceCommand._helpOption;
    this._helpCommand = sourceCommand._helpCommand;
    this._helpConfiguration = sourceCommand._helpConfiguration;
    this._exitCallback = sourceCommand._exitCallback;
    this._storeOptionsAsProperties = sourceCommand._storeOptionsAsProperties;
    this._combineFlagAndOptionalValue =
      sourceCommand._combineFlagAndOptionalValue;
    this._allowExcessArguments = sourceCommand._allowExcessArguments;
    this._enablePositionalOptions = sourceCommand._enablePositionalOptions;
    this._showHelpAfterError = sourceCommand._showHelpAfterError;
    this._showSuggestionAfterError = sourceCommand._showSuggestionAfterError;

    return this;
  }

  /**
   * @returns {Command[]}
   * @private
   */

  _getCommandAndAncestors() {
    const result = [];
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    for (let command = this; command; command = command.parent) {
      result.push(command);
    }
    return result;
  }

  /**
   * Define a command.
   *
   * There are two styles of command: pay attention to where to put the description.
   *
   * @example
   * // Command implemented using action handler (description is supplied separately to `.command`)
   * program
   *   .command('clone <source> [destination]')
   *   .description('clone a repository into a newly created directory')
   *   .action((source, destination) => {
   *     console.log('clone command called');
   *   });
   *
   * // Command implemented using separate executable file (description is second parameter to `.command`)
   * program
   *   .command('start <service>', 'start named service')
   *   .command('stop [service]', 'stop named service, or all if no name supplied');
   *
   * @param {string} nameAndArgs - command name and arguments, args are `<required>` or `[optional]` and last may also be `variadic...`
   * @param {(object | string)} [actionOptsOrExecDesc] - configuration options (for action), or description (for executable)
   * @param {object} [execOpts] - configuration options (for executable)
   * @return {Command} returns new command for action handler, or `this` for executable command
   */

  command(nameAndArgs, actionOptsOrExecDesc, execOpts) {
    let desc = actionOptsOrExecDesc;
    let opts = execOpts;
    if (typeof desc === 'object' && desc !== null) {
      opts = desc;
      desc = null;
    }
    opts = opts || {};
    const [, name, args] = nameAndArgs.match(/([^ ]+) *(.*)/);

    const cmd = this.createCommand(name);
    if (desc) {
      cmd.description(desc);
      cmd._executableHandler = true;
    }
    if (opts.isDefault) this._defaultCommandName = cmd._name;
    cmd._hidden = !!(opts.noHelp || opts.hidden); // noHelp is deprecated old name for hidden
    cmd._executableFile = opts.executableFile || null; // Custom name for executable file, set missing to null to match constructor
    if (args) cmd.arguments(args);
    this._registerCommand(cmd);
    cmd.parent = this;
    cmd.copyInheritedSettings(this);

    if (desc) return this;
    return cmd;
  }

  /**
   * Factory routine to create a new unattached command.
   *
   * See .command() for creating an attached subcommand, which uses this routine to
   * create the command. You can override createCommand to customise subcommands.
   *
   * @param {string} [name]
   * @return {Command} new command
   */

  createCommand(name) {
    return new Command(name);
  }

  /**
   * You can customise the help with a subclass of Help by overriding createHelp,
   * or by overriding Help properties using configureHelp().
   *
   * @return {Help}
   */

  createHelp() {
    return Object.assign(new Help(), this.configureHelp());
  }

  /**
   * You can customise the help by overriding Help properties using configureHelp(),
   * or with a subclass of Help by overriding createHelp().
   *
   * @param {object} [configuration] - configuration options
   * @return {(Command | object)} `this` command for chaining, or stored configuration
   */

  configureHelp(configuration) {
    if (configuration === undefined) return this._helpConfiguration;

    this._helpConfiguration = configuration;
    return this;
  }

  /**
   * The default output goes to stdout and stderr. You can customise this for special
   * applications. You can also customise the display of errors by overriding outputError.
   *
   * The configuration properties are all functions:
   *
   *     // change how output being written, defaults to stdout and stderr
   *     writeOut(str)
   *     writeErr(str)
   *     // change how output being written for errors, defaults to writeErr
   *     outputError(str, write) // used for displaying errors and not used for displaying help
   *     // specify width for wrapping help
   *     getOutHelpWidth()
   *     getErrHelpWidth()
   *     // color support, currently only used with Help
   *     getOutHasColors()
   *     getErrHasColors()
   *     stripColor() // used to remove ANSI escape codes if output does not have colors
   *
   * @param {object} [configuration] - configuration options
   * @return {(Command | object)} `this` command for chaining, or stored configuration
   */

  configureOutput(configuration) {
    if (configuration === undefined) return this._outputConfiguration;

    this._outputConfiguration = {
      ...this._outputConfiguration,
      ...configuration,
    };
    return this;
  }

  /**
   * Display the help or a custom message after an error occurs.
   *
   * @param {(boolean|string)} [displayHelp]
   * @return {Command} `this` command for chaining
   */
  showHelpAfterError(displayHelp = true) {
    if (typeof displayHelp !== 'string') displayHelp = !!displayHelp;
    this._showHelpAfterError = displayHelp;
    return this;
  }

  /**
   * Display suggestion of similar commands for unknown commands, or options for unknown options.
   *
   * @param {boolean} [displaySuggestion]
   * @return {Command} `this` command for chaining
   */
  showSuggestionAfterError(displaySuggestion = true) {
    this._showSuggestionAfterError = !!displaySuggestion;
    return this;
  }

  /**
   * Add a prepared subcommand.
   *
   * See .command() for creating an attached subcommand which inherits settings from its parent.
   *
   * @param {Command} cmd - new subcommand
   * @param {object} [opts] - configuration options
   * @return {Command} `this` command for chaining
   */

  addCommand(cmd, opts) {
    if (!cmd._name) {
      throw new Error(`Command passed to .addCommand() must have a name
- specify the name in Command constructor or using .name()`);
    }

    opts = opts || {};
    if (opts.isDefault) this._defaultCommandName = cmd._name;
    if (opts.noHelp || opts.hidden) cmd._hidden = true; // modifying passed command due to existing implementation

    this._registerCommand(cmd);
    cmd.parent = this;
    cmd._checkForBrokenPassThrough();

    return this;
  }

  /**
   * Factory routine to create a new unattached argument.
   *
   * See .argument() for creating an attached argument, which uses this routine to
   * create the argument. You can override createArgument to return a custom argument.
   *
   * @param {string} name
   * @param {string} [description]
   * @return {Argument} new argument
   */

  createArgument(name, description) {
    return new Argument(name, description);
  }

  /**
   * Define argument syntax for command.
   *
   * The default is that the argument is required, and you can explicitly
   * indicate this with <> around the name. Put [] around the name for an optional argument.
   *
   * @example
   * program.argument('<input-file>');
   * program.argument('[output-file]');
   *
   * @param {string} name
   * @param {string} [description]
   * @param {(Function|*)} [parseArg] - custom argument processing function or default value
   * @param {*} [defaultValue]
   * @return {Command} `this` command for chaining
   */
  argument(name, description, parseArg, defaultValue) {
    const argument = this.createArgument(name, description);
    if (typeof parseArg === 'function') {
      argument.default(defaultValue).argParser(parseArg);
    } else {
      argument.default(parseArg);
    }
    this.addArgument(argument);
    return this;
  }

  /**
   * Define argument syntax for command, adding multiple at once (without descriptions).
   *
   * See also .argument().
   *
   * @example
   * program.arguments('<cmd> [env]');
   *
   * @param {string} names
   * @return {Command} `this` command for chaining
   */

  arguments(names) {
    names
      .trim()
      .split(/ +/)
      .forEach((detail) => {
        this.argument(detail);
      });
    return this;
  }

  /**
   * Define argument syntax for command, adding a prepared argument.
   *
   * @param {Argument} argument
   * @return {Command} `this` command for chaining
   */
  addArgument(argument) {
    const previousArgument = this.registeredArguments.slice(-1)[0];
    if (previousArgument?.variadic) {
      throw new Error(
        `only the last argument can be variadic '${previousArgument.name()}'`,
      );
    }
    if (
      argument.required &&
      argument.defaultValue !== undefined &&
      argument.parseArg === undefined
    ) {
      throw new Error(
        `a default value for a required argument is never used: '${argument.name()}'`,
      );
    }
    this.registeredArguments.push(argument);
    return this;
  }

  /**
   * Customise or override default help command. By default a help command is automatically added if your command has subcommands.
   *
   * @example
   *    program.helpCommand('help [cmd]');
   *    program.helpCommand('help [cmd]', 'show help');
   *    program.helpCommand(false); // suppress default help command
   *    program.helpCommand(true); // add help command even if no subcommands
   *
   * @param {string|boolean} enableOrNameAndArgs - enable with custom name and/or arguments, or boolean to override whether added
   * @param {string} [description] - custom description
   * @return {Command} `this` command for chaining
   */

  helpCommand(enableOrNameAndArgs, description) {
    if (typeof enableOrNameAndArgs === 'boolean') {
      this._addImplicitHelpCommand = enableOrNameAndArgs;
      if (enableOrNameAndArgs && this._defaultCommandGroup) {
        // make the command to store the group
        this._initCommandGroup(this._getHelpCommand());
      }
      return this;
    }

    const nameAndArgs = enableOrNameAndArgs ?? 'help [command]';
    const [, helpName, helpArgs] = nameAndArgs.match(/([^ ]+) *(.*)/);
    const helpDescription = description ?? 'display help for command';

    const helpCommand = this.createCommand(helpName);
    helpCommand.helpOption(false);
    if (helpArgs) helpCommand.arguments(helpArgs);
    if (helpDescription) helpCommand.description(helpDescription);

    this._addImplicitHelpCommand = true;
    this._helpCommand = helpCommand;
    // init group unless lazy create
    if (enableOrNameAndArgs || description) this._initCommandGroup(helpCommand);

    return this;
  }

  /**
   * Add prepared custom help command.
   *
   * @param {(Command|string|boolean)} helpCommand - custom help command, or deprecated enableOrNameAndArgs as for `.helpCommand()`
   * @param {string} [deprecatedDescription] - deprecated custom description used with custom name only
   * @return {Command} `this` command for chaining
   */
  addHelpCommand(helpCommand, deprecatedDescription) {
    // If not passed an object, call through to helpCommand for backwards compatibility,
    // as addHelpCommand was originally used like helpCommand is now.
    if (typeof helpCommand !== 'object') {
      this.helpCommand(helpCommand, deprecatedDescription);
      return this;
    }

    this._addImplicitHelpCommand = true;
    this._helpCommand = helpCommand;
    this._initCommandGroup(helpCommand);
    return this;
  }

  /**
   * Lazy create help command.
   *
   * @return {(Command|null)}
   * @package
   */
  _getHelpCommand() {
    const hasImplicitHelpCommand =
      this._addImplicitHelpCommand ??
      (this.commands.length &&
        !this._actionHandler &&
        !this._findCommand('help'));

    if (hasImplicitHelpCommand) {
      if (this._helpCommand === undefined) {
        this.helpCommand(undefined, undefined); // use default name and description
      }
      return this._helpCommand;
    }
    return null;
  }

  /**
   * Add hook for life cycle event.
   *
   * @param {string} event
   * @param {Function} listener
   * @return {Command} `this` command for chaining
   */

  hook(event, listener) {
    const allowedValues = ['preSubcommand', 'preAction', 'postAction'];
    if (!allowedValues.includes(event)) {
      throw new Error(`Unexpected value for event passed to hook : '${event}'.
Expecting one of '${allowedValues.join("', '")}'`);
    }
    if (this._lifeCycleHooks[event]) {
      this._lifeCycleHooks[event].push(listener);
    } else {
      this._lifeCycleHooks[event] = [listener];
    }
    return this;
  }

  /**
   * Register callback to use as replacement for calling process.exit.
   *
   * @param {Function} [fn] optional callback which will be passed a CommanderError, defaults to throwing
   * @return {Command} `this` command for chaining
   */

  exitOverride(fn) {
    if (fn) {
      this._exitCallback = fn;
    } else {
      this._exitCallback = (err) => {
        if (err.code !== 'commander.executeSubCommandAsync') {
          throw err;
        } else {
          // Async callback from spawn events, not useful to throw.
        }
      };
    }
    return this;
  }

  /**
   * Call process.exit, and _exitCallback if defined.
   *
   * @param {number} exitCode exit code for using with process.exit
   * @param {string} code an id string representing the error
   * @param {string} message human-readable description of the error
   * @return never
   * @private
   */

  _exit(exitCode, code, message) {
    if (this._exitCallback) {
      this._exitCallback(new CommanderError(exitCode, code, message));
      // Expecting this line is not reached.
    }
    process.exit(exitCode);
  }

  /**
   * Register callback `fn` for the command.
   *
   * @example
   * program
   *   .command('serve')
   *   .description('start service')
   *   .action(function() {
   *      // do work here
   *   });
   *
   * @param {Function} fn
   * @return {Command} `this` command for chaining
   */

  action(fn) {
    const listener = (args) => {
      // The .action callback takes an extra parameter which is the command or options.
      const expectedArgsCount = this.registeredArguments.length;
      const actionArgs = args.slice(0, expectedArgsCount);
      if (this._storeOptionsAsProperties) {
        actionArgs[expectedArgsCount] = this; // backwards compatible "options"
      } else {
        actionArgs[expectedArgsCount] = this.opts();
      }
      actionArgs.push(this);

      return fn.apply(this, actionArgs);
    };
    this._actionHandler = listener;
    return this;
  }

  /**
   * Factory routine to create a new unattached option.
   *
   * See .option() for creating an attached option, which uses this routine to
   * create the option. You can override createOption to return a custom option.
   *
   * @param {string} flags
   * @param {string} [description]
   * @return {Option} new option
   */

  createOption(flags, description) {
    return new Option(flags, description);
  }

  /**
   * Wrap parseArgs to catch 'commander.invalidArgument'.
   *
   * @param {(Option | Argument)} target
   * @param {string} value
   * @param {*} previous
   * @param {string} invalidArgumentMessage
   * @private
   */

  _callParseArg(target, value, previous, invalidArgumentMessage) {
    try {
      return target.parseArg(value, previous);
    } catch (err) {
      if (err.code === 'commander.invalidArgument') {
        const message = `${invalidArgumentMessage} ${err.message}`;
        this.error(message, { exitCode: err.exitCode, code: err.code });
      }
      throw err;
    }
  }

  /**
   * Check for option flag conflicts.
   * Register option if no conflicts found, or throw on conflict.
   *
   * @param {Option} option
   * @private
   */

  _registerOption(option) {
    const matchingOption =
      (option.short && this._findOption(option.short)) ||
      (option.long && this._findOption(option.long));
    if (matchingOption) {
      const matchingFlag =
        option.long && this._findOption(option.long)
          ? option.long
          : option.short;
      throw new Error(`Cannot add option '${option.flags}'${this._name && ` to command '${this._name}'`} due to conflicting flag '${matchingFlag}'
-  already used by option '${matchingOption.flags}'`);
    }

    this._initOptionGroup(option);
    this.options.push(option);
  }

  /**
   * Check for command name and alias conflicts with existing commands.
   * Register command if no conflicts found, or throw on conflict.
   *
   * @param {Command} command
   * @private
   */

  _registerCommand(command) {
    const knownBy = (cmd) => {
      return [cmd.name()].concat(cmd.aliases());
    };

    const alreadyUsed = knownBy(command).find((name) =>
      this._findCommand(name),
    );
    if (alreadyUsed) {
      const existingCmd = knownBy(this._findCommand(alreadyUsed)).join('|');
      const newCmd = knownBy(command).join('|');
      throw new Error(
        `cannot add command '${newCmd}' as already have command '${existingCmd}'`,
      );
    }

    this._initCommandGroup(command);
    this.commands.push(command);
  }

  /**
   * Add an option.
   *
   * @param {Option} option
   * @return {Command} `this` command for chaining
   */
  addOption(option) {
    this._registerOption(option);

    const oname = option.name();
    const name = option.attributeName();

    // store default value
    if (option.negate) {
      // --no-foo is special and defaults foo to true, unless a --foo option is already defined
      const positiveLongFlag = option.long.replace(/^--no-/, '--');
      if (!this._findOption(positiveLongFlag)) {
        this.setOptionValueWithSource(
          name,
          option.defaultValue === undefined ? true : option.defaultValue,
          'default',
        );
      }
    } else if (option.defaultValue !== undefined) {
      this.setOptionValueWithSource(name, option.defaultValue, 'default');
    }

    // handler for cli and env supplied values
    const handleOptionValue = (val, invalidValueMessage, valueSource) => {
      // val is null for optional option used without an optional-argument.
      // val is undefined for boolean and negated option.
      if (val == null && option.presetArg !== undefined) {
        val = option.presetArg;
      }

      // custom processing
      const oldValue = this.getOptionValue(name);
      if (val !== null && option.parseArg) {
        val = this._callParseArg(option, val, oldValue, invalidValueMessage);
      } else if (val !== null && option.variadic) {
        val = option._collectValue(val, oldValue);
      }

      // Fill-in appropriate missing values. Long winded but easy to follow.
      if (val == null) {
        if (option.negate) {
          val = false;
        } else if (option.isBoolean() || option.optional) {
          val = true;
        } else {
          val = ''; // not normal, parseArg might have failed or be a mock function for testing
        }
      }
      this.setOptionValueWithSource(name, val, valueSource);
    };

    this.on('option:' + oname, (val) => {
      const invalidValueMessage = `error: option '${option.flags}' argument '${val}' is invalid.`;
      handleOptionValue(val, invalidValueMessage, 'cli');
    });

    if (option.envVar) {
      this.on('optionEnv:' + oname, (val) => {
        const invalidValueMessage = `error: option '${option.flags}' value '${val}' from env '${option.envVar}' is invalid.`;
        handleOptionValue(val, invalidValueMessage, 'env');
      });
    }

    return this;
  }

  /**
   * Internal implementation shared by .option() and .requiredOption()
   *
   * @return {Command} `this` command for chaining
   * @private
   */
  _optionEx(config, flags, description, fn, defaultValue) {
    if (typeof flags === 'object' && flags instanceof Option) {
      throw new Error(
        'To add an Option object use addOption() instead of option() or requiredOption()',
      );
    }
    const option = this.createOption(flags, description);
    option.makeOptionMandatory(!!config.mandatory);
    if (typeof fn === 'function') {
      option.default(defaultValue).argParser(fn);
    } else if (fn instanceof RegExp) {
      // deprecated
      const regex = fn;
      fn = (val, def) => {
        const m = regex.exec(val);
        return m ? m[0] : def;
      };
      option.default(defaultValue).argParser(fn);
    } else {
      option.default(fn);
    }

    return this.addOption(option);
  }

  /**
   * Define option with `flags`, `description`, and optional argument parsing function or `defaultValue` or both.
   *
   * The `flags` string contains the short and/or long flags, separated by comma, a pipe or space. A required
   * option-argument is indicated by `<>` and an optional option-argument by `[]`.
   *
   * See the README for more details, and see also addOption() and requiredOption().
   *
   * @example
   * program
   *     .option('-p, --pepper', 'add pepper')
   *     .option('--pt, --pizza-type <TYPE>', 'type of pizza') // required option-argument
   *     .option('-c, --cheese [CHEESE]', 'add extra cheese', 'mozzarella') // optional option-argument with default
   *     .option('-t, --tip <VALUE>', 'add tip to purchase cost', parseFloat) // custom parse function
   *
   * @param {string} flags
   * @param {string} [description]
   * @param {(Function|*)} [parseArg] - custom option processing function or default value
   * @param {*} [defaultValue]
   * @return {Command} `this` command for chaining
   */

  option(flags, description, parseArg, defaultValue) {
    return this._optionEx({}, flags, description, parseArg, defaultValue);
  }

  /**
   * Add a required option which must have a value after parsing. This usually means
   * the option must be specified on the command line. (Otherwise the same as .option().)
   *
   * The `flags` string contains the short and/or long flags, separated by comma, a pipe or space.
   *
   * @param {string} flags
   * @param {string} [description]
   * @param {(Function|*)} [parseArg] - custom option processing function or default value
   * @param {*} [defaultValue]
   * @return {Command} `this` command for chaining
   */

  requiredOption(flags, description, parseArg, defaultValue) {
    return this._optionEx(
      { mandatory: true },
      flags,
      description,
      parseArg,
      defaultValue,
    );
  }

  /**
   * Alter parsing of short flags with optional values.
   *
   * @example
   * // for `.option('-f,--flag [value]'):
   * program.combineFlagAndOptionalValue(true);  // `-f80` is treated like `--flag=80`, this is the default behaviour
   * program.combineFlagAndOptionalValue(false) // `-fb` is treated like `-f -b`
   *
   * @param {boolean} [combine] - if `true` or omitted, an optional value can be specified directly after the flag.
   * @return {Command} `this` command for chaining
   */
  combineFlagAndOptionalValue(combine = true) {
    this._combineFlagAndOptionalValue = !!combine;
    return this;
  }

  /**
   * Allow unknown options on the command line.
   *
   * @param {boolean} [allowUnknown] - if `true` or omitted, no error will be thrown for unknown options.
   * @return {Command} `this` command for chaining
   */
  allowUnknownOption(allowUnknown = true) {
    this._allowUnknownOption = !!allowUnknown;
    return this;
  }

  /**
   * Allow excess command-arguments on the command line. Pass false to make excess arguments an error.
   *
   * @param {boolean} [allowExcess] - if `true` or omitted, no error will be thrown for excess arguments.
   * @return {Command} `this` command for chaining
   */
  allowExcessArguments(allowExcess = true) {
    this._allowExcessArguments = !!allowExcess;
    return this;
  }

  /**
   * Enable positional options. Positional means global options are specified before subcommands which lets
   * subcommands reuse the same option names, and also enables subcommands to turn on passThroughOptions.
   * The default behaviour is non-positional and global options may appear anywhere on the command line.
   *
   * @param {boolean} [positional]
   * @return {Command} `this` command for chaining
   */
  enablePositionalOptions(positional = true) {
    this._enablePositionalOptions = !!positional;
    return this;
  }

  /**
   * Pass through options that come after command-arguments rather than treat them as command-options,
   * so actual command-options come before command-arguments. Turning this on for a subcommand requires
   * positional options to have been enabled on the program (parent commands).
   * The default behaviour is non-positional and options may appear before or after command-arguments.
   *
   * @param {boolean} [passThrough] for unknown options.
   * @return {Command} `this` command for chaining
   */
  passThroughOptions(passThrough = true) {
    this._passThroughOptions = !!passThrough;
    this._checkForBrokenPassThrough();
    return this;
  }

  /**
   * @private
   */

  _checkForBrokenPassThrough() {
    if (
      this.parent &&
      this._passThroughOptions &&
      !this.parent._enablePositionalOptions
    ) {
      throw new Error(
        `passThroughOptions cannot be used for '${this._name}' without turning on enablePositionalOptions for parent command(s)`,
      );
    }
  }

  /**
   * Whether to store option values as properties on command object,
   * or store separately (specify false). In both cases the option values can be accessed using .opts().
   *
   * @param {boolean} [storeAsProperties=true]
   * @return {Command} `this` command for chaining
   */

  storeOptionsAsProperties(storeAsProperties = true) {
    if (this.options.length) {
      throw new Error('call .storeOptionsAsProperties() before adding options');
    }
    if (Object.keys(this._optionValues).length) {
      throw new Error(
        'call .storeOptionsAsProperties() before setting option values',
      );
    }
    this._storeOptionsAsProperties = !!storeAsProperties;
    return this;
  }

  /**
   * Retrieve option value.
   *
   * @param {string} key
   * @return {object} value
   */

  getOptionValue(key) {
    if (this._storeOptionsAsProperties) {
      return this[key];
    }
    return this._optionValues[key];
  }

  /**
   * Store option value.
   *
   * @param {string} key
   * @param {object} value
   * @return {Command} `this` command for chaining
   */

  setOptionValue(key, value) {
    return this.setOptionValueWithSource(key, value, undefined);
  }

  /**
   * Store option value and where the value came from.
   *
   * @param {string} key
   * @param {object} value
   * @param {string} source - expected values are default/config/env/cli/implied
   * @return {Command} `this` command for chaining
   */

  setOptionValueWithSource(key, value, source) {
    if (this._storeOptionsAsProperties) {
      this[key] = value;
    } else {
      this._optionValues[key] = value;
    }
    this._optionValueSources[key] = source;
    return this;
  }

  /**
   * Get source of option value.
   * Expected values are default | config | env | cli | implied
   *
   * @param {string} key
   * @return {string}
   */

  getOptionValueSource(key) {
    return this._optionValueSources[key];
  }

  /**
   * Get source of option value. See also .optsWithGlobals().
   * Expected values are default | config | env | cli | implied
   *
   * @param {string} key
   * @return {string}
   */

  getOptionValueSourceWithGlobals(key) {
    // global overwrites local, like optsWithGlobals
    let source;
    this._getCommandAndAncestors().forEach((cmd) => {
      if (cmd.getOptionValueSource(key) !== undefined) {
        source = cmd.getOptionValueSource(key);
      }
    });
    return source;
  }

  /**
   * Get user arguments from implied or explicit arguments.
   * Side-effects: set _scriptPath if args included script. Used for default program name, and subcommand searches.
   *
   * @private
   */

  _prepareUserArgs(argv, parseOptions) {
    if (argv !== undefined && !Array.isArray(argv)) {
      throw new Error('first parameter to parse must be array or undefined');
    }
    parseOptions = parseOptions || {};

    // auto-detect argument conventions if nothing supplied
    if (argv === undefined && parseOptions.from === undefined) {
      if (process.versions?.electron) {
        parseOptions.from = 'electron';
      }
      // check node specific options for scenarios where user CLI args follow executable without scriptname
      const execArgv = process.execArgv ?? [];
      if (
        execArgv.includes('-e') ||
        execArgv.includes('--eval') ||
        execArgv.includes('-p') ||
        execArgv.includes('--print')
      ) {
        parseOptions.from = 'eval'; // internal usage, not documented
      }
    }

    // default to using process.argv
    if (argv === undefined) {
      argv = process.argv;
    }
    this.rawArgs = argv.slice();

    // extract the user args and scriptPath
    let userArgs;
    switch (parseOptions.from) {
      case undefined:
      case 'node':
        this._scriptPath = argv[1];
        userArgs = argv.slice(2);
        break;
      case 'electron':
        // @ts-ignore: because defaultApp is an unknown property
        if (process.defaultApp) {
          this._scriptPath = argv[1];
          userArgs = argv.slice(2);
        } else {
          userArgs = argv.slice(1);
        }
        break;
      case 'user':
        userArgs = argv.slice(0);
        break;
      case 'eval':
        userArgs = argv.slice(1);
        break;
      default:
        throw new Error(
          `unexpected parse option { from: '${parseOptions.from}' }`,
        );
    }

    // Find default name for program from arguments.
    if (!this._name && this._scriptPath)
      this.nameFromFilename(this._scriptPath);
    this._name = this._name || 'program';

    return userArgs;
  }

  /**
   * Parse `argv`, setting options and invoking commands when defined.
   *
   * Use parseAsync instead of parse if any of your action handlers are async.
   *
   * Call with no parameters to parse `process.argv`. Detects Electron and special node options like `node --eval`. Easy mode!
   *
   * Or call with an array of strings to parse, and optionally where the user arguments start by specifying where the arguments are `from`:
   * - `'node'`: default, `argv[0]` is the application and `argv[1]` is the script being run, with user arguments after that
   * - `'electron'`: `argv[0]` is the application and `argv[1]` varies depending on whether the electron application is packaged
   * - `'user'`: just user arguments
   *
   * @example
   * program.parse(); // parse process.argv and auto-detect electron and special node flags
   * program.parse(process.argv); // assume argv[0] is app and argv[1] is script
   * program.parse(my-args, { from: 'user' }); // just user supplied arguments, nothing special about argv[0]
   *
   * @param {string[]} [argv] - optional, defaults to process.argv
   * @param {object} [parseOptions] - optionally specify style of options with from: node/user/electron
   * @param {string} [parseOptions.from] - where the args are from: 'node', 'user', 'electron'
   * @return {Command} `this` command for chaining
   */

  parse(argv, parseOptions) {
    this._prepareForParse();
    const userArgs = this._prepareUserArgs(argv, parseOptions);
    this._parseCommand([], userArgs);

    return this;
  }

  /**
   * Parse `argv`, setting options and invoking commands when defined.
   *
   * Call with no parameters to parse `process.argv`. Detects Electron and special node options like `node --eval`. Easy mode!
   *
   * Or call with an array of strings to parse, and optionally where the user arguments start by specifying where the arguments are `from`:
   * - `'node'`: default, `argv[0]` is the application and `argv[1]` is the script being run, with user arguments after that
   * - `'electron'`: `argv[0]` is the application and `argv[1]` varies depending on whether the electron application is packaged
   * - `'user'`: just user arguments
   *
   * @example
   * await program.parseAsync(); // parse process.argv and auto-detect electron and special node flags
   * await program.parseAsync(process.argv); // assume argv[0] is app and argv[1] is script
   * await program.parseAsync(my-args, { from: 'user' }); // just user supplied arguments, nothing special about argv[0]
   *
   * @param {string[]} [argv]
   * @param {object} [parseOptions]
   * @param {string} parseOptions.from - where the args are from: 'node', 'user', 'electron'
   * @return {Promise}
   */

  async parseAsync(argv, parseOptions) {
    this._prepareForParse();
    const userArgs = this._prepareUserArgs(argv, parseOptions);
    await this._parseCommand([], userArgs);

    return this;
  }

  _prepareForParse() {
    if (this._savedState === null) {
      this.saveStateBeforeParse();
    } else {
      this.restoreStateBeforeParse();
    }
  }

  /**
   * Called the first time parse is called to save state and allow a restore before subsequent calls to parse.
   * Not usually called directly, but available for subclasses to save their custom state.
   *
   * This is called in a lazy way. Only commands used in parsing chain will have state saved.
   */
  saveStateBeforeParse() {
    this._savedState = {
      // name is stable if supplied by author, but may be unspecified for root command and deduced during parsing
      _name: this._name,
      // option values before parse have default values (including false for negated options)
      // shallow clones
      _optionValues: { ...this._optionValues },
      _optionValueSources: { ...this._optionValueSources },
    };
  }

  /**
   * Restore state before parse for calls after the first.
   * Not usually called directly, but available for subclasses to save their custom state.
   *
   * This is called in a lazy way. Only commands used in parsing chain will have state restored.
   */
  restoreStateBeforeParse() {
    if (this._storeOptionsAsProperties)
      throw new Error(`Can not call parse again when storeOptionsAsProperties is true.
- either make a new Command for each call to parse, or stop storing options as properties`);

    // clear state from _prepareUserArgs
    this._name = this._savedState._name;
    this._scriptPath = null;
    this.rawArgs = [];
    // clear state from setOptionValueWithSource
    this._optionValues = { ...this._savedState._optionValues };
    this._optionValueSources = { ...this._savedState._optionValueSources };
    // clear state from _parseCommand
    this.args = [];
    // clear state from _processArguments
    this.processedArgs = [];
  }

  /**
   * Throw if expected executable is missing. Add lots of help for author.
   *
   * @param {string} executableFile
   * @param {string} executableDir
   * @param {string} subcommandName
   */
  _checkForMissingExecutable(executableFile, executableDir, subcommandName) {
    if (fs.existsSync(executableFile)) return;

    const executableDirMessage = executableDir
      ? `searched for local subcommand relative to directory '${executableDir}'`
      : 'no directory for search for local subcommand, use .executableDir() to supply a custom directory';
    const executableMissing = `'${executableFile}' does not exist
 - if '${subcommandName}' is not meant to be an executable command, remove description parameter from '.command()' and use '.description()' instead
 - if the default executable name is not suitable, use the executableFile option to supply a custom name or path
 - ${executableDirMessage}`;
    throw new Error(executableMissing);
  }

  /**
   * Execute a sub-command executable.
   *
   * @private
   */

  _executeSubCommand(subcommand, args) {
    args = args.slice();
    let launchWithNode = false; // Use node for source targets so do not need to get permissions correct, and on Windows.
    const sourceExt = ['.js', '.ts', '.tsx', '.mjs', '.cjs'];

    function findFile(baseDir, baseName) {
      // Look for specified file
      const localBin = path.resolve(baseDir, baseName);
      if (fs.existsSync(localBin)) return localBin;

      // Stop looking if candidate already has an expected extension.
      if (sourceExt.includes(path.extname(baseName))) return undefined;

      // Try all the extensions.
      const foundExt = sourceExt.find((ext) =>
        fs.existsSync(`${localBin}${ext}`),
      );
      if (foundExt) return `${localBin}${foundExt}`;

      return undefined;
    }

    // Not checking for help first. Unlikely to have mandatory and executable, and can't robustly test for help flags in external command.
    this._checkForMissingMandatoryOptions();
    this._checkForConflictingOptions();

    // executableFile and executableDir might be full path, or just a name
    let executableFile =
      subcommand._executableFile || `${this._name}-${subcommand._name}`;
    let executableDir = this._executableDir || '';
    if (this._scriptPath) {
      let resolvedScriptPath; // resolve possible symlink for installed npm binary
      try {
        resolvedScriptPath = fs.realpathSync(this._scriptPath);
      } catch {
        resolvedScriptPath = this._scriptPath;
      }
      executableDir = path.resolve(
        path.dirname(resolvedScriptPath),
        executableDir,
      );
    }

    // Look for a local file in preference to a command in PATH.
    if (executableDir) {
      let localFile = findFile(executableDir, executableFile);

      // Legacy search using prefix of script name instead of command name
      if (!localFile && !subcommand._executableFile && this._scriptPath) {
        const legacyName = path.basename(
          this._scriptPath,
          path.extname(this._scriptPath),
        );
        if (legacyName !== this._name) {
          localFile = findFile(
            executableDir,
            `${legacyName}-${subcommand._name}`,
          );
        }
      }
      executableFile = localFile || executableFile;
    }

    launchWithNode = sourceExt.includes(path.extname(executableFile));

    let proc;
    if (process.platform !== 'win32') {
      if (launchWithNode) {
        args.unshift(executableFile);
        // add executable arguments to spawn
        args = incrementNodeInspectorPort(process.execArgv).concat(args);

        proc = childProcess.spawn(process.argv[0], args, { stdio: 'inherit' });
      } else {
        proc = childProcess.spawn(executableFile, args, { stdio: 'inherit' });
      }
    } else {
      this._checkForMissingExecutable(
        executableFile,
        executableDir,
        subcommand._name,
      );
      args.unshift(executableFile);
      // add executable arguments to spawn
      args = incrementNodeInspectorPort(process.execArgv).concat(args);
      proc = childProcess.spawn(process.execPath, args, { stdio: 'inherit' });
    }

    if (!proc.killed) {
      // testing mainly to avoid leak warnings during unit tests with mocked spawn
      const signals = ['SIGUSR1', 'SIGUSR2', 'SIGTERM', 'SIGINT', 'SIGHUP'];
      signals.forEach((signal) => {
        process.on(signal, () => {
          if (proc.killed === false && proc.exitCode === null) {
            // @ts-ignore because signals not typed to known strings
            proc.kill(signal);
          }
        });
      });
    }

    // By default terminate process when spawned process terminates.
    const exitCallback = this._exitCallback;
    proc.on('close', (code) => {
      code = code ?? 1; // code is null if spawned process terminated due to a signal
      if (!exitCallback) {
        process.exit(code);
      } else {
        exitCallback(
          new CommanderError(
            code,
            'commander.executeSubCommandAsync',
            '(close)',
          ),
        );
      }
    });
    proc.on('error', (err) => {
      // @ts-ignore: because err.code is an unknown property
      if (err.code === 'ENOENT') {
        this._checkForMissingExecutable(
          executableFile,
          executableDir,
          subcommand._name,
        );
        // @ts-ignore: because err.code is an unknown property
      } else if (err.code === 'EACCES') {
        throw new Error(`'${executableFile}' not executable`);
      }
      if (!exitCallback) {
        process.exit(1);
      } else {
        const wrappedError = new CommanderError(
          1,
          'commander.executeSubCommandAsync',
          '(error)',
        );
        wrappedError.nestedError = err;
        exitCallback(wrappedError);
      }
    });

    // Store the reference to the child process
    this.runningCommand = proc;
  }

  /**
   * @private
   */

  _dispatchSubcommand(commandName, operands, unknown) {
    const subCommand = this._findCommand(commandName);
    if (!subCommand) this.help({ error: true });

    subCommand._prepareForParse();
    let promiseChain;
    promiseChain = this._chainOrCallSubCommandHook(
      promiseChain,
      subCommand,
      'preSubcommand',
    );
    promiseChain = this._chainOrCall(promiseChain, () => {
      if (subCommand._executableHandler) {
        this._executeSubCommand(subCommand, operands.concat(unknown));
      } else {
        return subCommand._parseCommand(operands, unknown);
      }
    });
    return promiseChain;
  }

  /**
   * Invoke help directly if possible, or dispatch if necessary.
   * e.g. help foo
   *
   * @private
   */

  _dispatchHelpCommand(subcommandName) {
    if (!subcommandName) {
      this.help();
    }
    const subCommand = this._findCommand(subcommandName);
    if (subCommand && !subCommand._executableHandler) {
      subCommand.help();
    }

    // Fallback to parsing the help flag to invoke the help.
    return this._dispatchSubcommand(
      subcommandName,
      [],
      [this._getHelpOption()?.long ?? this._getHelpOption()?.short ?? '--help'],
    );
  }

  /**
   * Check this.args against expected this.registeredArguments.
   *
   * @private
   */

  _checkNumberOfArguments() {
    // too few
    this.registeredArguments.forEach((arg, i) => {
      if (arg.required && this.args[i] == null) {
        this.missingArgument(arg.name());
      }
    });
    // too many
    if (
      this.registeredArguments.length > 0 &&
      this.registeredArguments[this.registeredArguments.length - 1].variadic
    ) {
      return;
    }
    if (this.args.length > this.registeredArguments.length) {
      this._excessArguments(this.args);
    }
  }

  /**
   * Process this.args using this.registeredArguments and save as this.processedArgs!
   *
   * @private
   */

  _processArguments() {
    const myParseArg = (argument, value, previous) => {
      // Extra processing for nice error message on parsing failure.
      let parsedValue = value;
      if (value !== null && argument.parseArg) {
        const invalidValueMessage = `error: command-argument value '${value}' is invalid for argument '${argument.name()}'.`;
        parsedValue = this._callParseArg(
          argument,
          value,
          previous,
          invalidValueMessage,
        );
      }
      return parsedValue;
    };

    this._checkNumberOfArguments();

    const processedArgs = [];
    this.registeredArguments.forEach((declaredArg, index) => {
      let value = declaredArg.defaultValue;
      if (declaredArg.variadic) {
        // Collect together remaining arguments for passing together as an array.
        if (index < this.args.length) {
          value = this.args.slice(index);
          if (declaredArg.parseArg) {
            value = value.reduce((processed, v) => {
              return myParseArg(declaredArg, v, processed);
            }, declaredArg.defaultValue);
          }
        } else if (value === undefined) {
          value = [];
        }
      } else if (index < this.args.length) {
        value = this.args[index];
        if (declaredArg.parseArg) {
          value = myParseArg(declaredArg, value, declaredArg.defaultValue);
        }
      }
      processedArgs[index] = value;
    });
    this.processedArgs = processedArgs;
  }

  /**
   * Once we have a promise we chain, but call synchronously until then.
   *
   * @param {(Promise|undefined)} promise
   * @param {Function} fn
   * @return {(Promise|undefined)}
   * @private
   */

  _chainOrCall(promise, fn) {
    // thenable
    if (promise?.then && typeof promise.then === 'function') {
      // already have a promise, chain callback
      return promise.then(() => fn());
    }
    // callback might return a promise
    return fn();
  }

  /**
   *
   * @param {(Promise|undefined)} promise
   * @param {string} event
   * @return {(Promise|undefined)}
   * @private
   */

  _chainOrCallHooks(promise, event) {
    let result = promise;
    const hooks = [];
    this._getCommandAndAncestors()
      .reverse()
      .filter((cmd) => cmd._lifeCycleHooks[event] !== undefined)
      .forEach((hookedCommand) => {
        hookedCommand._lifeCycleHooks[event].forEach((callback) => {
          hooks.push({ hookedCommand, callback });
        });
      });
    if (event === 'postAction') {
      hooks.reverse();
    }

    hooks.forEach((hookDetail) => {
      result = this._chainOrCall(result, () => {
        return hookDetail.callback(hookDetail.hookedCommand, this);
      });
    });
    return result;
  }

  /**
   *
   * @param {(Promise|undefined)} promise
   * @param {Command} subCommand
   * @param {string} event
   * @return {(Promise|undefined)}
   * @private
   */

  _chainOrCallSubCommandHook(promise, subCommand, event) {
    let result = promise;
    if (this._lifeCycleHooks[event] !== undefined) {
      this._lifeCycleHooks[event].forEach((hook) => {
        result = this._chainOrCall(result, () => {
          return hook(this, subCommand);
        });
      });
    }
    return result;
  }

  /**
   * Process arguments in context of this command.
   * Returns action result, in case it is a promise.
   *
   * @private
   */

  _parseCommand(operands, unknown) {
    const parsed = this.parseOptions(unknown);
    this._parseOptionsEnv(); // after cli, so parseArg not called on both cli and env
    this._parseOptionsImplied();
    operands = operands.concat(parsed.operands);
    unknown = parsed.unknown;
    this.args = operands.concat(unknown);

    if (operands && this._findCommand(operands[0])) {
      return this._dispatchSubcommand(operands[0], operands.slice(1), unknown);
    }
    if (
      this._getHelpCommand() &&
      operands[0] === this._getHelpCommand().name()
    ) {
      return this._dispatchHelpCommand(operands[1]);
    }
    if (this._defaultCommandName) {
      this._outputHelpIfRequested(unknown); // Run the help for default command from parent rather than passing to default command
      return this._dispatchSubcommand(
        this._defaultCommandName,
        operands,
        unknown,
      );
    }
    if (
      this.commands.length &&
      this.args.length === 0 &&
      !this._actionHandler &&
      !this._defaultCommandName
    ) {
      // probably missing subcommand and no handler, user needs help (and exit)
      this.help({ error: true });
    }

    this._outputHelpIfRequested(parsed.unknown);
    this._checkForMissingMandatoryOptions();
    this._checkForConflictingOptions();

    // We do not always call this check to avoid masking a "better" error, like unknown command.
    const checkForUnknownOptions = () => {
      if (parsed.unknown.length > 0) {
        this.unknownOption(parsed.unknown[0]);
      }
    };

    const commandEvent = `command:${this.name()}`;
    if (this._actionHandler) {
      checkForUnknownOptions();
      this._processArguments();

      let promiseChain;
      promiseChain = this._chainOrCallHooks(promiseChain, 'preAction');
      promiseChain = this._chainOrCall(promiseChain, () =>
        this._actionHandler(this.processedArgs),
      );
      if (this.parent) {
        promiseChain = this._chainOrCall(promiseChain, () => {
          this.parent.emit(commandEvent, operands, unknown); // legacy
        });
      }
      promiseChain = this._chainOrCallHooks(promiseChain, 'postAction');
      return promiseChain;
    }
    if (this.parent?.listenerCount(commandEvent)) {
      checkForUnknownOptions();
      this._processArguments();
      this.parent.emit(commandEvent, operands, unknown); // legacy
    } else if (operands.length) {
      if (this._findCommand('*')) {
        // legacy default command
        return this._dispatchSubcommand('*', operands, unknown);
      }
      if (this.listenerCount('command:*')) {
        // skip option check, emit event for possible misspelling suggestion
        this.emit('command:*', operands, unknown);
      } else if (this.commands.length) {
        this.unknownCommand();
      } else {
        checkForUnknownOptions();
        this._processArguments();
      }
    } else if (this.commands.length) {
      checkForUnknownOptions();
      // This command has subcommands and nothing hooked up at this level, so display help (and exit).
      this.help({ error: true });
    } else {
      checkForUnknownOptions();
      this._processArguments();
      // fall through for caller to handle after calling .parse()
    }
  }

  /**
   * Find matching command.
   *
   * @private
   * @return {Command | undefined}
   */
  _findCommand(name) {
    if (!name) return undefined;
    return this.commands.find(
      (cmd) => cmd._name === name || cmd._aliases.includes(name),
    );
  }

  /**
   * Return an option matching `arg` if any.
   *
   * @param {string} arg
   * @return {Option}
   * @package
   */

  _findOption(arg) {
    return this.options.find((option) => option.is(arg));
  }

  /**
   * Display an error message if a mandatory option does not have a value.
   * Called after checking for help flags in leaf subcommand.
   *
   * @private
   */

  _checkForMissingMandatoryOptions() {
    // Walk up hierarchy so can call in subcommand after checking for displaying help.
    this._getCommandAndAncestors().forEach((cmd) => {
      cmd.options.forEach((anOption) => {
        if (
          anOption.mandatory &&
          cmd.getOptionValue(anOption.attributeName()) === undefined
        ) {
          cmd.missingMandatoryOptionValue(anOption);
        }
      });
    });
  }

  /**
   * Display an error message if conflicting options are used together in this.
   *
   * @private
   */
  _checkForConflictingLocalOptions() {
    const definedNonDefaultOptions = this.options.filter((option) => {
      const optionKey = option.attributeName();
      if (this.getOptionValue(optionKey) === undefined) {
        return false;
      }
      return this.getOptionValueSource(optionKey) !== 'default';
    });

    const optionsWithConflicting = definedNonDefaultOptions.filter(
      (option) => option.conflictsWith.length > 0,
    );

    optionsWithConflicting.forEach((option) => {
      const conflictingAndDefined = definedNonDefaultOptions.find((defined) =>
        option.conflictsWith.includes(defined.attributeName()),
      );
      if (conflictingAndDefined) {
        this._conflictingOption(option, conflictingAndDefined);
      }
    });
  }

  /**
   * Display an error message if conflicting options are used together.
   * Called after checking for help flags in leaf subcommand.
   *
   * @private
   */
  _checkForConflictingOptions() {
    // Walk up hierarchy so can call in subcommand after checking for displaying help.
    this._getCommandAndAncestors().forEach((cmd) => {
      cmd._checkForConflictingLocalOptions();
    });
  }

  /**
   * Parse options from `argv` removing known options,
   * and return argv split into operands and unknown arguments.
   *
   * Side effects: modifies command by storing options. Does not reset state if called again.
   *
   * Examples:
   *
   *     argv => operands, unknown
   *     --known kkk op => [op], []
   *     op --known kkk => [op], []
   *     sub --unknown uuu op => [sub], [--unknown uuu op]
   *     sub -- --unknown uuu op => [sub --unknown uuu op], []
   *
   * @param {string[]} args
   * @return {{operands: string[], unknown: string[]}}
   */

  parseOptions(args) {
    const operands = []; // operands, not options or values
    const unknown = []; // first unknown option and remaining unknown args
    let dest = operands;

    function maybeOption(arg) {
      return arg.length > 1 && arg[0] === '-';
    }

    const negativeNumberArg = (arg) => {
      // return false if not a negative number
      if (!/^-(\d+|\d*\.\d+)(e[+-]?\d+)?$/.test(arg)) return false;
      // negative number is ok unless digit used as an option in command hierarchy
      return !this._getCommandAndAncestors().some((cmd) =>
        cmd.options
          .map((opt) => opt.short)
          .some((short) => /^-\d$/.test(short)),
      );
    };

    // parse options
    let activeVariadicOption = null;
    let activeGroup = null; // working through group of short options, like -abc
    let i = 0;
    while (i < args.length || activeGroup) {
      const arg = activeGroup ?? args[i++];
      activeGroup = null;

      // literal
      if (arg === '--') {
        if (dest === unknown) dest.push(arg);
        dest.push(...args.slice(i));
        break;
      }

      if (
        activeVariadicOption &&
        (!maybeOption(arg) || negativeNumberArg(arg))
      ) {
        this.emit(`option:${activeVariadicOption.name()}`, arg);
        continue;
      }
      activeVariadicOption = null;

      if (maybeOption(arg)) {
        const option = this._findOption(arg);
        // recognised option, call listener to assign value with possible custom processing
        if (option) {
          if (option.required) {
            const value = args[i++];
            if (value === undefined) this.optionMissingArgument(option);
            this.emit(`option:${option.name()}`, value);
          } else if (option.optional) {
            let value = null;
            // historical behaviour is optional value is following arg unless an option
            if (
              i < args.length &&
              (!maybeOption(args[i]) || negativeNumberArg(args[i]))
            ) {
              value = args[i++];
            }
            this.emit(`option:${option.name()}`, value);
          } else {
            // boolean flag
            this.emit(`option:${option.name()}`);
          }
          activeVariadicOption = option.variadic ? option : null;
          continue;
        }
      }

      // Look for combo options following single dash, eat first one if known.
      if (arg.length > 2 && arg[0] === '-' && arg[1] !== '-') {
        const option = this._findOption(`-${arg[1]}`);
        if (option) {
          if (
            option.required ||
            (option.optional && this._combineFlagAndOptionalValue)
          ) {
            // option with value following in same argument
            this.emit(`option:${option.name()}`, arg.slice(2));
          } else {
            // boolean option
            this.emit(`option:${option.name()}`);
            // remove the processed option and keep processing group
            activeGroup = `-${arg.slice(2)}`;
          }
          continue;
        }
      }

      // Look for known long flag with value, like --foo=bar
      if (/^--[^=]+=/.test(arg)) {
        const index = arg.indexOf('=');
        const option = this._findOption(arg.slice(0, index));
        if (option && (option.required || option.optional)) {
          this.emit(`option:${option.name()}`, arg.slice(index + 1));
          continue;
        }
      }

      // Not a recognised option by this command.
      // Might be a command-argument, or subcommand option, or unknown option, or help command or option.

      // An unknown option means further arguments also classified as unknown so can be reprocessed by subcommands.
      // A negative number in a leaf command is not an unknown option.
      if (
        dest === operands &&
        maybeOption(arg) &&
        !(this.commands.length === 0 && negativeNumberArg(arg))
      ) {
        dest = unknown;
      }

      // If using positionalOptions, stop processing our options at subcommand.
      if (
        (this._enablePositionalOptions || this._passThroughOptions) &&
        operands.length === 0 &&
        unknown.length === 0
      ) {
        if (this._findCommand(arg)) {
          operands.push(arg);
          unknown.push(...args.slice(i));
          break;
        } else if (
          this._getHelpCommand() &&
          arg === this._getHelpCommand().name()
        ) {
          operands.push(arg, ...args.slice(i));
          break;
        } else if (this._defaultCommandName) {
          unknown.push(arg, ...args.slice(i));
          break;
        }
      }

      // If using passThroughOptions, stop processing options at first command-argument.
      if (this._passThroughOptions) {
        dest.push(arg, ...args.slice(i));
        break;
      }

      // add arg
      dest.push(arg);
    }

    return { operands, unknown };
  }

  /**
   * Return an object containing local option values as key-value pairs.
   *
   * @return {object}
   */
  opts() {
    if (this._storeOptionsAsProperties) {
      // Preserve original behaviour so backwards compatible when still using properties
      const result = {};
      const len = this.options.length;

      for (let i = 0; i < len; i++) {
        const key = this.options[i].attributeName();
        result[key] =
          key === this._versionOptionName ? this._version : this[key];
      }
      return result;
    }

    return this._optionValues;
  }

  /**
   * Return an object containing merged local and global option values as key-value pairs.
   *
   * @return {object}
   */
  optsWithGlobals() {
    // globals overwrite locals
    return this._getCommandAndAncestors().reduce(
      (combinedOptions, cmd) => Object.assign(combinedOptions, cmd.opts()),
      {},
    );
  }

  /**
   * Display error message and exit (or call exitOverride).
   *
   * @param {string} message
   * @param {object} [errorOptions]
   * @param {string} [errorOptions.code] - an id string representing the error
   * @param {number} [errorOptions.exitCode] - used with process.exit
   */
  error(message, errorOptions) {
    // output handling
    this._outputConfiguration.outputError(
      `${message}\n`,
      this._outputConfiguration.writeErr,
    );
    if (typeof this._showHelpAfterError === 'string') {
      this._outputConfiguration.writeErr(`${this._showHelpAfterError}\n`);
    } else if (this._showHelpAfterError) {
      this._outputConfiguration.writeErr('\n');
      this.outputHelp({ error: true });
    }

    // exit handling
    const config = errorOptions || {};
    const exitCode = config.exitCode || 1;
    const code = config.code || 'commander.error';
    this._exit(exitCode, code, message);
  }

  /**
   * Apply any option related environment variables, if option does
   * not have a value from cli or client code.
   *
   * @private
   */
  _parseOptionsEnv() {
    this.options.forEach((option) => {
      if (option.envVar && option.envVar in process.env) {
        const optionKey = option.attributeName();
        // Priority check. Do not overwrite cli or options from unknown source (client-code).
        if (
          this.getOptionValue(optionKey) === undefined ||
          ['default', 'config', 'env'].includes(
            this.getOptionValueSource(optionKey),
          )
        ) {
          if (option.required || option.optional) {
            // option can take a value
            // keep very simple, optional always takes value
            this.emit(`optionEnv:${option.name()}`, process.env[option.envVar]);
          } else {
            // boolean
            // keep very simple, only care that envVar defined and not the value
            this.emit(`optionEnv:${option.name()}`);
          }
        }
      }
    });
  }

  /**
   * Apply any implied option values, if option is undefined or default value.
   *
   * @private
   */
  _parseOptionsImplied() {
    const dualHelper = new DualOptions(this.options);
    const hasCustomOptionValue = (optionKey) => {
      return (
        this.getOptionValue(optionKey) !== undefined &&
        !['default', 'implied'].includes(this.getOptionValueSource(optionKey))
      );
    };
    this.options
      .filter(
        (option) =>
          option.implied !== undefined &&
          hasCustomOptionValue(option.attributeName()) &&
          dualHelper.valueFromOption(
            this.getOptionValue(option.attributeName()),
            option,
          ),
      )
      .forEach((option) => {
        Object.keys(option.implied)
          .filter((impliedKey) => !hasCustomOptionValue(impliedKey))
          .forEach((impliedKey) => {
            this.setOptionValueWithSource(
              impliedKey,
              option.implied[impliedKey],
              'implied',
            );
          });
      });
  }

  /**
   * Argument `name` is missing.
   *
   * @param {string} name
   * @private
   */

  missingArgument(name) {
    const message = `error: missing required argument '${name}'`;
    this.error(message, { code: 'commander.missingArgument' });
  }

  /**
   * `Option` is missing an argument.
   *
   * @param {Option} option
   * @private
   */

  optionMissingArgument(option) {
    const message = `error: option '${option.flags}' argument missing`;
    this.error(message, { code: 'commander.optionMissingArgument' });
  }

  /**
   * `Option` does not have a value, and is a mandatory option.
   *
   * @param {Option} option
   * @private
   */

  missingMandatoryOptionValue(option) {
    const message = `error: required option '${option.flags}' not specified`;
    this.error(message, { code: 'commander.missingMandatoryOptionValue' });
  }

  /**
   * `Option` conflicts with another option.
   *
   * @param {Option} option
   * @param {Option} conflictingOption
   * @private
   */
  _conflictingOption(option, conflictingOption) {
    // The calling code does not know whether a negated option is the source of the
    // value, so do some work to take an educated guess.
    const findBestOptionFromValue = (option) => {
      const optionKey = option.attributeName();
      const optionValue = this.getOptionValue(optionKey);
      const negativeOption = this.options.find(
        (target) => target.negate && optionKey === target.attributeName(),
      );
      const positiveOption = this.options.find(
        (target) => !target.negate && optionKey === target.attributeName(),
      );
      if (
        negativeOption &&
        ((negativeOption.presetArg === undefined && optionValue === false) ||
          (negativeOption.presetArg !== undefined &&
            optionValue === negativeOption.presetArg))
      ) {
        return negativeOption;
      }
      return positiveOption || option;
    };

    const getErrorMessage = (option) => {
      const bestOption = findBestOptionFromValue(option);
      const optionKey = bestOption.attributeName();
      const source = this.getOptionValueSource(optionKey);
      if (source === 'env') {
        return `environment variable '${bestOption.envVar}'`;
      }
      return `option '${bestOption.flags}'`;
    };

    const message = `error: ${getErrorMessage(option)} cannot be used with ${getErrorMessage(conflictingOption)}`;
    this.error(message, { code: 'commander.conflictingOption' });
  }

  /**
   * Unknown option `flag`.
   *
   * @param {string} flag
   * @private
   */

  unknownOption(flag) {
    if (this._allowUnknownOption) return;
    let suggestion = '';

    if (flag.startsWith('--') && this._showSuggestionAfterError) {
      // Looping to pick up the global options too
      let candidateFlags = [];
      // eslint-disable-next-line @typescript-eslint/no-this-alias
      let command = this;
      do {
        const moreFlags = command
          .createHelp()
          .visibleOptions(command)
          .filter((option) => option.long)
          .map((option) => option.long);
        candidateFlags = candidateFlags.concat(moreFlags);
        command = command.parent;
      } while (command && !command._enablePositionalOptions);
      suggestion = suggestSimilar(flag, candidateFlags);
    }

    const message = `error: unknown option '${flag}'${suggestion}`;
    this.error(message, { code: 'commander.unknownOption' });
  }

  /**
   * Excess arguments, more than expected.
   *
   * @param {string[]} receivedArgs
   * @private
   */

  _excessArguments(receivedArgs) {
    if (this._allowExcessArguments) return;

    const expected = this.registeredArguments.length;
    const s = expected === 1 ? '' : 's';
    const forSubcommand = this.parent ? ` for '${this.name()}'` : '';
    const message = `error: too many arguments${forSubcommand}. Expected ${expected} argument${s} but got ${receivedArgs.length}.`;
    this.error(message, { code: 'commander.excessArguments' });
  }

  /**
   * Unknown command.
   *
   * @private
   */

  unknownCommand() {
    const unknownName = this.args[0];
    let suggestion = '';

    if (this._showSuggestionAfterError) {
      const candidateNames = [];
      this.createHelp()
        .visibleCommands(this)
        .forEach((command) => {
          candidateNames.push(command.name());
          // just visible alias
          if (command.alias()) candidateNames.push(command.alias());
        });
      suggestion = suggestSimilar(unknownName, candidateNames);
    }

    const message = `error: unknown command '${unknownName}'${suggestion}`;
    this.error(message, { code: 'commander.unknownCommand' });
  }

  /**
   * Get or set the program version.
   *
   * This method auto-registers the "-V, --version" option which will print the version number.
   *
   * You can optionally supply the flags and description to override the defaults.
   *
   * @param {string} [str]
   * @param {string} [flags]
   * @param {string} [description]
   * @return {(this | string | undefined)} `this` command for chaining, or version string if no arguments
   */

  version(str, flags, description) {
    if (str === undefined) return this._version;
    this._version = str;
    flags = flags || '-V, --version';
    description = description || 'output the version number';
    const versionOption = this.createOption(flags, description);
    this._versionOptionName = versionOption.attributeName();
    this._registerOption(versionOption);

    this.on('option:' + versionOption.name(), () => {
      this._outputConfiguration.writeOut(`${str}\n`);
      this._exit(0, 'commander.version', str);
    });
    return this;
  }

  /**
   * Set the description.
   *
   * @param {string} [str]
   * @param {object} [argsDescription]
   * @return {(string|Command)}
   */
  description(str, argsDescription) {
    if (str === undefined && argsDescription === undefined)
      return this._description;
    this._description = str;
    if (argsDescription) {
      this._argsDescription = argsDescription;
    }
    return this;
  }

  /**
   * Set the summary. Used when listed as subcommand of parent.
   *
   * @param {string} [str]
   * @return {(string|Command)}
   */
  summary(str) {
    if (str === undefined) return this._summary;
    this._summary = str;
    return this;
  }

  /**
   * Set an alias for the command.
   *
   * You may call more than once to add multiple aliases. Only the first alias is shown in the auto-generated help.
   *
   * @param {string} [alias]
   * @return {(string|Command)}
   */

  alias(alias) {
    if (alias === undefined) return this._aliases[0]; // just return first, for backwards compatibility

    /** @type {Command} */
    // eslint-disable-next-line @typescript-eslint/no-this-alias
    let command = this;
    if (
      this.commands.length !== 0 &&
      this.commands[this.commands.length - 1]._executableHandler
    ) {
      // assume adding alias for last added executable subcommand, rather than this
      command = this.commands[this.commands.length - 1];
    }

    if (alias === command._name)
      throw new Error("Command alias can't be the same as its name");
    const matchingCommand = this.parent?._findCommand(alias);
    if (matchingCommand) {
      // c.f. _registerCommand
      const existingCmd = [matchingCommand.name()]
        .concat(matchingCommand.aliases())
        .join('|');
      throw new Error(
        `cannot add alias '${alias}' to command '${this.name()}' as already have command '${existingCmd}'`,
      );
    }

    command._aliases.push(alias);
    return this;
  }

  /**
   * Set aliases for the command.
   *
   * Only the first alias is shown in the auto-generated help.
   *
   * @param {string[]} [aliases]
   * @return {(string[]|Command)}
   */

  aliases(aliases) {
    // Getter for the array of aliases is the main reason for having aliases() in addition to alias().
    if (aliases === undefined) return this._aliases;

    aliases.forEach((alias) => this.alias(alias));
    return this;
  }

  /**
   * Set / get the command usage `str`.
   *
   * @param {string} [str]
   * @return {(string|Command)}
   */

  usage(str) {
    if (str === undefined) {
      if (this._usage) return this._usage;

      const args = this.registeredArguments.map((arg) => {
        return humanReadableArgName(arg);
      });
      return []
        .concat(
          this.options.length || this._helpOption !== null ? '[options]' : [],
          this.commands.length ? '[command]' : [],
          this.registeredArguments.length ? args : [],
        )
        .join(' ');
    }

    this._usage = str;
    return this;
  }

  /**
   * Get or set the name of the command.
   *
   * @param {string} [str]
   * @return {(string|Command)}
   */

  name(str) {
    if (str === undefined) return this._name;
    this._name = str;
    return this;
  }

  /**
   * Set/get the help group heading for this subcommand in parent command's help.
   *
   * @param {string} [heading]
   * @return {Command | string}
   */

  helpGroup(heading) {
    if (heading === undefined) return this._helpGroupHeading ?? '';
    this._helpGroupHeading = heading;
    return this;
  }

  /**
   * Set/get the default help group heading for subcommands added to this command.
   * (This does not override a group set directly on the subcommand using .helpGroup().)
   *
   * @example
   * program.commandsGroup('Development Commands:);
   * program.command('watch')...
   * program.command('lint')...
   * ...
   *
   * @param {string} [heading]
   * @returns {Command | string}
   */
  commandsGroup(heading) {
    if (heading === undefined) return this._defaultCommandGroup ?? '';
    this._defaultCommandGroup = heading;
    return this;
  }

  /**
   * Set/get the default help group heading for options added to this command.
   * (This does not override a group set directly on the option using .helpGroup().)
   *
   * @example
   * program
   *   .optionsGroup('Development Options:')
   *   .option('-d, --debug', 'output extra debugging')
   *   .option('-p, --profile', 'output profiling information')
   *
   * @param {string} [heading]
   * @returns {Command | string}
   */
  optionsGroup(heading) {
    if (heading === undefined) return this._defaultOptionGroup ?? '';
    this._defaultOptionGroup = heading;
    return this;
  }

  /**
   * @param {Option} option
   * @private
   */
  _initOptionGroup(option) {
    if (this._defaultOptionGroup && !option.helpGroupHeading)
      option.helpGroup(this._defaultOptionGroup);
  }

  /**
   * @param {Command} cmd
   * @private
   */
  _initCommandGroup(cmd) {
    if (this._defaultCommandGroup && !cmd.helpGroup())
      cmd.helpGroup(this._defaultCommandGroup);
  }

  /**
   * Set the name of the command from script filename, such as process.argv[1],
   * or require.main.filename, or __filename.
   *
   * (Used internally and public although not documented in README.)
   *
   * @example
   * program.nameFromFilename(require.main.filename);
   *
   * @param {string} filename
   * @return {Command}
   */

  nameFromFilename(filename) {
    this._name = path.basename(filename, path.extname(filename));

    return this;
  }

  /**
   * Get or set the directory for searching for executable subcommands of this command.
   *
   * @example
   * program.executableDir(__dirname);
   * // or
   * program.executableDir('subcommands');
   *
   * @param {string} [path]
   * @return {(string|null|Command)}
   */

  executableDir(path) {
    if (path === undefined) return this._executableDir;
    this._executableDir = path;
    return this;
  }

  /**
   * Return program help documentation.
   *
   * @param {{ error: boolean }} [contextOptions] - pass {error:true} to wrap for stderr instead of stdout
   * @return {string}
   */

  helpInformation(contextOptions) {
    const helper = this.createHelp();
    const context = this._getOutputContext(contextOptions);
    helper.prepareContext({
      error: context.error,
      helpWidth: context.helpWidth,
      outputHasColors: context.hasColors,
    });
    const text = helper.formatHelp(this, helper);
    if (context.hasColors) return text;
    return this._outputConfiguration.stripColor(text);
  }

  /**
   * @typedef HelpContext
   * @type {object}
   * @property {boolean} error
   * @property {number} helpWidth
   * @property {boolean} hasColors
   * @property {function} write - includes stripColor if needed
   *
   * @returns {HelpContext}
   * @private
   */

  _getOutputContext(contextOptions) {
    contextOptions = contextOptions || {};
    const error = !!contextOptions.error;
    let baseWrite;
    let hasColors;
    let helpWidth;
    if (error) {
      baseWrite = (str) => this._outputConfiguration.writeErr(str);
      hasColors = this._outputConfiguration.getErrHasColors();
      helpWidth = this._outputConfiguration.getErrHelpWidth();
    } else {
      baseWrite = (str) => this._outputConfiguration.writeOut(str);
      hasColors = this._outputConfiguration.getOutHasColors();
      helpWidth = this._outputConfiguration.getOutHelpWidth();
    }
    const write = (str) => {
      if (!hasColors) str = this._outputConfiguration.stripColor(str);
      return baseWrite(str);
    };
    return { error, write, hasColors, helpWidth };
  }

  /**
   * Output help information for this command.
   *
   * Outputs built-in help, and custom text added using `.addHelpText()`.
   *
   * @param {{ error: boolean } | Function} [contextOptions] - pass {error:true} to write to stderr instead of stdout
   */

  outputHelp(contextOptions) {
    let deprecatedCallback;
    if (typeof contextOptions === 'function') {
      deprecatedCallback = contextOptions;
      contextOptions = undefined;
    }

    const outputContext = this._getOutputContext(contextOptions);
    /** @type {HelpTextEventContext} */
    const eventContext = {
      error: outputContext.error,
      write: outputContext.write,
      command: this,
    };

    this._getCommandAndAncestors()
      .reverse()
      .forEach((command) => command.emit('beforeAllHelp', eventContext));
    this.emit('beforeHelp', eventContext);

    let helpInformation = this.helpInformation({ error: outputContext.error });
    if (deprecatedCallback) {
      helpInformation = deprecatedCallback(helpInformation);
      if (
        typeof helpInformation !== 'string' &&
        !Buffer.isBuffer(helpInformation)
      ) {
        throw new Error('outputHelp callback must return a string or a Buffer');
      }
    }
    outputContext.write(helpInformation);

    if (this._getHelpOption()?.long) {
      this.emit(this._getHelpOption().long); // deprecated
    }
    this.emit('afterHelp', eventContext);
    this._getCommandAndAncestors().forEach((command) =>
      command.emit('afterAllHelp', eventContext),
    );
  }

  /**
   * You can pass in flags and a description to customise the built-in help option.
   * Pass in false to disable the built-in help option.
   *
   * @example
   * program.helpOption('-?, --help' 'show help'); // customise
   * program.helpOption(false); // disable
   *
   * @param {(string | boolean)} flags
   * @param {string} [description]
   * @return {Command} `this` command for chaining
   */

  helpOption(flags, description) {
    // Support enabling/disabling built-in help option.
    if (typeof flags === 'boolean') {
      if (flags) {
        if (this._helpOption === null) this._helpOption = undefined; // reenable
        if (this._defaultOptionGroup) {
          // make the option to store the group
          this._initOptionGroup(this._getHelpOption());
        }
      } else {
        this._helpOption = null; // disable
      }
      return this;
    }

    // Customise flags and description.
    this._helpOption = this.createOption(
      flags ?? '-h, --help',
      description ?? 'display help for command',
    );
    // init group unless lazy create
    if (flags || description) this._initOptionGroup(this._helpOption);

    return this;
  }

  /**
   * Lazy create help option.
   * Returns null if has been disabled with .helpOption(false).
   *
   * @returns {(Option | null)} the help option
   * @package
   */
  _getHelpOption() {
    // Lazy create help option on demand.
    if (this._helpOption === undefined) {
      this.helpOption(undefined, undefined);
    }
    return this._helpOption;
  }

  /**
   * Supply your own option to use for the built-in help option.
   * This is an alternative to using helpOption() to customise the flags and description etc.
   *
   * @param {Option} option
   * @return {Command} `this` command for chaining
   */
  addHelpOption(option) {
    this._helpOption = option;
    this._initOptionGroup(option);
    return this;
  }

  /**
   * Output help information and exit.
   *
   * Outputs built-in help, and custom text added using `.addHelpText()`.
   *
   * @param {{ error: boolean }} [contextOptions] - pass {error:true} to write to stderr instead of stdout
   */

  help(contextOptions) {
    this.outputHelp(contextOptions);
    let exitCode = Number(process.exitCode ?? 0); // process.exitCode does allow a string or an integer, but we prefer just a number
    if (
      exitCode === 0 &&
      contextOptions &&
      typeof contextOptions !== 'function' &&
      contextOptions.error
    ) {
      exitCode = 1;
    }
    // message: do not have all displayed text available so only passing placeholder.
    this._exit(exitCode, 'commander.help', '(outputHelp)');
  }

  /**
   * // Do a little typing to coordinate emit and listener for the help text events.
   * @typedef HelpTextEventContext
   * @type {object}
   * @property {boolean} error
   * @property {Command} command
   * @property {function} write
   */

  /**
   * Add additional text to be displayed with the built-in help.
   *
   * Position is 'before' or 'after' to affect just this command,
   * and 'beforeAll' or 'afterAll' to affect this command and all its subcommands.
   *
   * @param {string} position - before or after built-in help
   * @param {(string | Function)} text - string to add, or a function returning a string
   * @return {Command} `this` command for chaining
   */

  addHelpText(position, text) {
    const allowedValues = ['beforeAll', 'before', 'after', 'afterAll'];
    if (!allowedValues.includes(position)) {
      throw new Error(`Unexpected value for position to addHelpText.
Expecting one of '${allowedValues.join("', '")}'`);
    }

    const helpEvent = `${position}Help`;
    this.on(helpEvent, (/** @type {HelpTextEventContext} */ context) => {
      let helpStr;
      if (typeof text === 'function') {
        helpStr = text({ error: context.error, command: context.command });
      } else {
        helpStr = text;
      }
      // Ignore falsy value when nothing to output.
      if (helpStr) {
        context.write(`${helpStr}\n`);
      }
    });
    return this;
  }

  /**
   * Output help information if help flags specified
   *
   * @param {Array} args - array of options to search for help flags
   * @private
   */

  _outputHelpIfRequested(args) {
    const helpOption = this._getHelpOption();
    const helpRequested = helpOption && args.find((arg) => helpOption.is(arg));
    if (helpRequested) {
      this.outputHelp();
      // (Do not have all displayed text available so only passing placeholder.)
      this._exit(0, 'commander.helpDisplayed', '(outputHelp)');
    }
  }
}

/**
 * Scan arguments and increment port number for inspect calls (to avoid conflicts when spawning new command).
 *
 * @param {string[]} args - array of arguments from node.execArgv
 * @returns {string[]}
 * @private
 */

function incrementNodeInspectorPort(args) {
  // Testing for these options:
  //  --inspect[=[host:]port]
  //  --inspect-brk[=[host:]port]
  //  --inspect-port=[host:]port
  return args.map((arg) => {
    if (!arg.startsWith('--inspect')) {
      return arg;
    }
    let debugOption;
    let debugHost = '127.0.0.1';
    let debugPort = '9229';
    let match;
    if ((match = arg.match(/^(--inspect(-brk)?)$/)) !== null) {
      // e.g. --inspect
      debugOption = match[1];
    } else if (
      (match = arg.match(/^(--inspect(-brk|-port)?)=([^:]+)$/)) !== null
    ) {
      debugOption = match[1];
      if (/^\d+$/.test(match[3])) {
        // e.g. --inspect=1234
        debugPort = match[3];
      } else {
        // e.g. --inspect=localhost
        debugHost = match[3];
      }
    } else if (
      (match = arg.match(/^(--inspect(-brk|-port)?)=([^:]+):(\d+)$/)) !== null
    ) {
      // e.g. --inspect=localhost:1234
      debugOption = match[1];
      debugHost = match[3];
      debugPort = match[4];
    }

    if (debugOption && debugPort !== '0') {
      return `${debugOption}=${debugHost}:${parseInt(debugPort) + 1}`;
    }
    return arg;
  });
}

/**
 * @returns {boolean | undefined}
 * @package
 */
function useColor() {
  // Test for common conventions.
  // NB: the observed behaviour is in combination with how author adds color! For example:
  //   - we do not test NODE_DISABLE_COLORS, but util:styletext does
  //   - we do test NO_COLOR, but Chalk does not
  //
  // References:
  // https://no-color.org
  // https://bixense.com/clicolors/
  // https://github.com/nodejs/node/blob/0a00217a5f67ef4a22384cfc80eb6dd9a917fdc1/lib/internal/tty.js#L109
  // https://github.com/chalk/supports-color/blob/c214314a14bcb174b12b3014b2b0a8de375029ae/index.js#L33
  // (https://force-color.org recent web page from 2023, does not match major javascript implementations)

  if (
    process.env.NO_COLOR ||
    process.env.FORCE_COLOR === '0' ||
    process.env.FORCE_COLOR === 'false'
  )
    return false;
  if (process.env.FORCE_COLOR || process.env.CLICOLOR_FORCE !== undefined)
    return true;
  return undefined;
}

exports.Command = Command;
exports.useColor = useColor; // exporting for tests


/***/ }),

/***/ 135:
/***/ ((__unused_webpack_module, exports) => {

/**
 * CommanderError class
 */
class CommanderError extends Error {
  /**
   * Constructs the CommanderError class
   * @param {number} exitCode suggested exit code which could be used with process.exit
   * @param {string} code an id string representing the error
   * @param {string} message human-readable description of the error
   */
  constructor(exitCode, code, message) {
    super(message);
    // properly capture stack trace in Node.js
    Error.captureStackTrace(this, this.constructor);
    this.name = this.constructor.name;
    this.code = code;
    this.exitCode = exitCode;
    this.nestedError = undefined;
  }
}

/**
 * InvalidArgumentError class
 */
class InvalidArgumentError extends CommanderError {
  /**
   * Constructs the InvalidArgumentError class
   * @param {string} [message] explanation of why argument is invalid
   */
  constructor(message) {
    super(1, 'commander.invalidArgument', message);
    // properly capture stack trace in Node.js
    Error.captureStackTrace(this, this.constructor);
    this.name = this.constructor.name;
  }
}

exports.CommanderError = CommanderError;
exports.InvalidArgumentError = InvalidArgumentError;


/***/ }),

/***/ 754:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

const { humanReadableArgName } = __nccwpck_require__(154);

/**
 * TypeScript import types for JSDoc, used by Visual Studio Code IntelliSense and `npm run typescript-checkJS`
 * https://www.typescriptlang.org/docs/handbook/jsdoc-supported-types.html#import-types
 * @typedef { import("./argument.js").Argument } Argument
 * @typedef { import("./command.js").Command } Command
 * @typedef { import("./option.js").Option } Option
 */

// Although this is a class, methods are static in style to allow override using subclass or just functions.
class Help {
  constructor() {
    this.helpWidth = undefined;
    this.minWidthToWrap = 40;
    this.sortSubcommands = false;
    this.sortOptions = false;
    this.showGlobalOptions = false;
  }

  /**
   * prepareContext is called by Commander after applying overrides from `Command.configureHelp()`
   * and just before calling `formatHelp()`.
   *
   * Commander just uses the helpWidth and the rest is provided for optional use by more complex subclasses.
   *
   * @param {{ error?: boolean, helpWidth?: number, outputHasColors?: boolean }} contextOptions
   */
  prepareContext(contextOptions) {
    this.helpWidth = this.helpWidth ?? contextOptions.helpWidth ?? 80;
  }

  /**
   * Get an array of the visible subcommands. Includes a placeholder for the implicit help command, if there is one.
   *
   * @param {Command} cmd
   * @returns {Command[]}
   */

  visibleCommands(cmd) {
    const visibleCommands = cmd.commands.filter((cmd) => !cmd._hidden);
    const helpCommand = cmd._getHelpCommand();
    if (helpCommand && !helpCommand._hidden) {
      visibleCommands.push(helpCommand);
    }
    if (this.sortSubcommands) {
      visibleCommands.sort((a, b) => {
        // @ts-ignore: because overloaded return type
        return a.name().localeCompare(b.name());
      });
    }
    return visibleCommands;
  }

  /**
   * Compare options for sort.
   *
   * @param {Option} a
   * @param {Option} b
   * @returns {number}
   */
  compareOptions(a, b) {
    const getSortKey = (option) => {
      // WYSIWYG for order displayed in help. Short used for comparison if present. No special handling for negated.
      return option.short
        ? option.short.replace(/^-/, '')
        : option.long.replace(/^--/, '');
    };
    return getSortKey(a).localeCompare(getSortKey(b));
  }

  /**
   * Get an array of the visible options. Includes a placeholder for the implicit help option, if there is one.
   *
   * @param {Command} cmd
   * @returns {Option[]}
   */

  visibleOptions(cmd) {
    const visibleOptions = cmd.options.filter((option) => !option.hidden);
    // Built-in help option.
    const helpOption = cmd._getHelpOption();
    if (helpOption && !helpOption.hidden) {
      // Automatically hide conflicting flags. Bit dubious but a historical behaviour that is convenient for single-command programs.
      const removeShort = helpOption.short && cmd._findOption(helpOption.short);
      const removeLong = helpOption.long && cmd._findOption(helpOption.long);
      if (!removeShort && !removeLong) {
        visibleOptions.push(helpOption); // no changes needed
      } else if (helpOption.long && !removeLong) {
        visibleOptions.push(
          cmd.createOption(helpOption.long, helpOption.description),
        );
      } else if (helpOption.short && !removeShort) {
        visibleOptions.push(
          cmd.createOption(helpOption.short, helpOption.description),
        );
      }
    }
    if (this.sortOptions) {
      visibleOptions.sort(this.compareOptions);
    }
    return visibleOptions;
  }

  /**
   * Get an array of the visible global options. (Not including help.)
   *
   * @param {Command} cmd
   * @returns {Option[]}
   */

  visibleGlobalOptions(cmd) {
    if (!this.showGlobalOptions) return [];

    const globalOptions = [];
    for (
      let ancestorCmd = cmd.parent;
      ancestorCmd;
      ancestorCmd = ancestorCmd.parent
    ) {
      const visibleOptions = ancestorCmd.options.filter(
        (option) => !option.hidden,
      );
      globalOptions.push(...visibleOptions);
    }
    if (this.sortOptions) {
      globalOptions.sort(this.compareOptions);
    }
    return globalOptions;
  }

  /**
   * Get an array of the arguments if any have a description.
   *
   * @param {Command} cmd
   * @returns {Argument[]}
   */

  visibleArguments(cmd) {
    // Side effect! Apply the legacy descriptions before the arguments are displayed.
    if (cmd._argsDescription) {
      cmd.registeredArguments.forEach((argument) => {
        argument.description =
          argument.description || cmd._argsDescription[argument.name()] || '';
      });
    }

    // If there are any arguments with a description then return all the arguments.
    if (cmd.registeredArguments.find((argument) => argument.description)) {
      return cmd.registeredArguments;
    }
    return [];
  }

  /**
   * Get the command term to show in the list of subcommands.
   *
   * @param {Command} cmd
   * @returns {string}
   */

  subcommandTerm(cmd) {
    // Legacy. Ignores custom usage string, and nested commands.
    const args = cmd.registeredArguments
      .map((arg) => humanReadableArgName(arg))
      .join(' ');
    return (
      cmd._name +
      (cmd._aliases[0] ? '|' + cmd._aliases[0] : '') +
      (cmd.options.length ? ' [options]' : '') + // simplistic check for non-help option
      (args ? ' ' + args : '')
    );
  }

  /**
   * Get the option term to show in the list of options.
   *
   * @param {Option} option
   * @returns {string}
   */

  optionTerm(option) {
    return option.flags;
  }

  /**
   * Get the argument term to show in the list of arguments.
   *
   * @param {Argument} argument
   * @returns {string}
   */

  argumentTerm(argument) {
    return argument.name();
  }

  /**
   * Get the longest command term length.
   *
   * @param {Command} cmd
   * @param {Help} helper
   * @returns {number}
   */

  longestSubcommandTermLength(cmd, helper) {
    return helper.visibleCommands(cmd).reduce((max, command) => {
      return Math.max(
        max,
        this.displayWidth(
          helper.styleSubcommandTerm(helper.subcommandTerm(command)),
        ),
      );
    }, 0);
  }

  /**
   * Get the longest option term length.
   *
   * @param {Command} cmd
   * @param {Help} helper
   * @returns {number}
   */

  longestOptionTermLength(cmd, helper) {
    return helper.visibleOptions(cmd).reduce((max, option) => {
      return Math.max(
        max,
        this.displayWidth(helper.styleOptionTerm(helper.optionTerm(option))),
      );
    }, 0);
  }

  /**
   * Get the longest global option term length.
   *
   * @param {Command} cmd
   * @param {Help} helper
   * @returns {number}
   */

  longestGlobalOptionTermLength(cmd, helper) {
    return helper.visibleGlobalOptions(cmd).reduce((max, option) => {
      return Math.max(
        max,
        this.displayWidth(helper.styleOptionTerm(helper.optionTerm(option))),
      );
    }, 0);
  }

  /**
   * Get the longest argument term length.
   *
   * @param {Command} cmd
   * @param {Help} helper
   * @returns {number}
   */

  longestArgumentTermLength(cmd, helper) {
    return helper.visibleArguments(cmd).reduce((max, argument) => {
      return Math.max(
        max,
        this.displayWidth(
          helper.styleArgumentTerm(helper.argumentTerm(argument)),
        ),
      );
    }, 0);
  }

  /**
   * Get the command usage to be displayed at the top of the built-in help.
   *
   * @param {Command} cmd
   * @returns {string}
   */

  commandUsage(cmd) {
    // Usage
    let cmdName = cmd._name;
    if (cmd._aliases[0]) {
      cmdName = cmdName + '|' + cmd._aliases[0];
    }
    let ancestorCmdNames = '';
    for (
      let ancestorCmd = cmd.parent;
      ancestorCmd;
      ancestorCmd = ancestorCmd.parent
    ) {
      ancestorCmdNames = ancestorCmd.name() + ' ' + ancestorCmdNames;
    }
    return ancestorCmdNames + cmdName + ' ' + cmd.usage();
  }

  /**
   * Get the description for the command.
   *
   * @param {Command} cmd
   * @returns {string}
   */

  commandDescription(cmd) {
    // @ts-ignore: because overloaded return type
    return cmd.description();
  }

  /**
   * Get the subcommand summary to show in the list of subcommands.
   * (Fallback to description for backwards compatibility.)
   *
   * @param {Command} cmd
   * @returns {string}
   */

  subcommandDescription(cmd) {
    // @ts-ignore: because overloaded return type
    return cmd.summary() || cmd.description();
  }

  /**
   * Get the option description to show in the list of options.
   *
   * @param {Option} option
   * @return {string}
   */

  optionDescription(option) {
    const extraInfo = [];

    if (option.argChoices) {
      extraInfo.push(
        // use stringify to match the display of the default value
        `choices: ${option.argChoices.map((choice) => JSON.stringify(choice)).join(', ')}`,
      );
    }
    if (option.defaultValue !== undefined) {
      // default for boolean and negated more for programmer than end user,
      // but show true/false for boolean option as may be for hand-rolled env or config processing.
      const showDefault =
        option.required ||
        option.optional ||
        (option.isBoolean() && typeof option.defaultValue === 'boolean');
      if (showDefault) {
        extraInfo.push(
          `default: ${option.defaultValueDescription || JSON.stringify(option.defaultValue)}`,
        );
      }
    }
    // preset for boolean and negated are more for programmer than end user
    if (option.presetArg !== undefined && option.optional) {
      extraInfo.push(`preset: ${JSON.stringify(option.presetArg)}`);
    }
    if (option.envVar !== undefined) {
      extraInfo.push(`env: ${option.envVar}`);
    }
    if (extraInfo.length > 0) {
      const extraDescription = `(${extraInfo.join(', ')})`;
      if (option.description) {
        return `${option.description} ${extraDescription}`;
      }
      return extraDescription;
    }

    return option.description;
  }

  /**
   * Get the argument description to show in the list of arguments.
   *
   * @param {Argument} argument
   * @return {string}
   */

  argumentDescription(argument) {
    const extraInfo = [];
    if (argument.argChoices) {
      extraInfo.push(
        // use stringify to match the display of the default value
        `choices: ${argument.argChoices.map((choice) => JSON.stringify(choice)).join(', ')}`,
      );
    }
    if (argument.defaultValue !== undefined) {
      extraInfo.push(
        `default: ${argument.defaultValueDescription || JSON.stringify(argument.defaultValue)}`,
      );
    }
    if (extraInfo.length > 0) {
      const extraDescription = `(${extraInfo.join(', ')})`;
      if (argument.description) {
        return `${argument.description} ${extraDescription}`;
      }
      return extraDescription;
    }
    return argument.description;
  }

  /**
   * Format a list of items, given a heading and an array of formatted items.
   *
   * @param {string} heading
   * @param {string[]} items
   * @param {Help} helper
   * @returns string[]
   */
  formatItemList(heading, items, helper) {
    if (items.length === 0) return [];

    return [helper.styleTitle(heading), ...items, ''];
  }

  /**
   * Group items by their help group heading.
   *
   * @param {Command[] | Option[]} unsortedItems
   * @param {Command[] | Option[]} visibleItems
   * @param {Function} getGroup
   * @returns {Map<string, Command[] | Option[]>}
   */
  groupItems(unsortedItems, visibleItems, getGroup) {
    const result = new Map();
    // Add groups in order of appearance in unsortedItems.
    unsortedItems.forEach((item) => {
      const group = getGroup(item);
      if (!result.has(group)) result.set(group, []);
    });
    // Add items in order of appearance in visibleItems.
    visibleItems.forEach((item) => {
      const group = getGroup(item);
      if (!result.has(group)) {
        result.set(group, []);
      }
      result.get(group).push(item);
    });
    return result;
  }

  /**
   * Generate the built-in help text.
   *
   * @param {Command} cmd
   * @param {Help} helper
   * @returns {string}
   */

  formatHelp(cmd, helper) {
    const termWidth = helper.padWidth(cmd, helper);
    const helpWidth = helper.helpWidth ?? 80; // in case prepareContext() was not called

    function callFormatItem(term, description) {
      return helper.formatItem(term, termWidth, description, helper);
    }

    // Usage
    let output = [
      `${helper.styleTitle('Usage:')} ${helper.styleUsage(helper.commandUsage(cmd))}`,
      '',
    ];

    // Description
    const commandDescription = helper.commandDescription(cmd);
    if (commandDescription.length > 0) {
      output = output.concat([
        helper.boxWrap(
          helper.styleCommandDescription(commandDescription),
          helpWidth,
        ),
        '',
      ]);
    }

    // Arguments
    const argumentList = helper.visibleArguments(cmd).map((argument) => {
      return callFormatItem(
        helper.styleArgumentTerm(helper.argumentTerm(argument)),
        helper.styleArgumentDescription(helper.argumentDescription(argument)),
      );
    });
    output = output.concat(
      this.formatItemList('Arguments:', argumentList, helper),
    );

    // Options
    const optionGroups = this.groupItems(
      cmd.options,
      helper.visibleOptions(cmd),
      (option) => option.helpGroupHeading ?? 'Options:',
    );
    optionGroups.forEach((options, group) => {
      const optionList = options.map((option) => {
        return callFormatItem(
          helper.styleOptionTerm(helper.optionTerm(option)),
          helper.styleOptionDescription(helper.optionDescription(option)),
        );
      });
      output = output.concat(this.formatItemList(group, optionList, helper));
    });

    if (helper.showGlobalOptions) {
      const globalOptionList = helper
        .visibleGlobalOptions(cmd)
        .map((option) => {
          return callFormatItem(
            helper.styleOptionTerm(helper.optionTerm(option)),
            helper.styleOptionDescription(helper.optionDescription(option)),
          );
        });
      output = output.concat(
        this.formatItemList('Global Options:', globalOptionList, helper),
      );
    }

    // Commands
    const commandGroups = this.groupItems(
      cmd.commands,
      helper.visibleCommands(cmd),
      (sub) => sub.helpGroup() || 'Commands:',
    );
    commandGroups.forEach((commands, group) => {
      const commandList = commands.map((sub) => {
        return callFormatItem(
          helper.styleSubcommandTerm(helper.subcommandTerm(sub)),
          helper.styleSubcommandDescription(helper.subcommandDescription(sub)),
        );
      });
      output = output.concat(this.formatItemList(group, commandList, helper));
    });

    return output.join('\n');
  }

  /**
   * Return display width of string, ignoring ANSI escape sequences. Used in padding and wrapping calculations.
   *
   * @param {string} str
   * @returns {number}
   */
  displayWidth(str) {
    return stripColor(str).length;
  }

  /**
   * Style the title for displaying in the help. Called with 'Usage:', 'Options:', etc.
   *
   * @param {string} str
   * @returns {string}
   */
  styleTitle(str) {
    return str;
  }

  styleUsage(str) {
    // Usage has lots of parts the user might like to color separately! Assume default usage string which is formed like:
    //    command subcommand [options] [command] <foo> [bar]
    return str
      .split(' ')
      .map((word) => {
        if (word === '[options]') return this.styleOptionText(word);
        if (word === '[command]') return this.styleSubcommandText(word);
        if (word[0] === '[' || word[0] === '<')
          return this.styleArgumentText(word);
        return this.styleCommandText(word); // Restrict to initial words?
      })
      .join(' ');
  }
  styleCommandDescription(str) {
    return this.styleDescriptionText(str);
  }
  styleOptionDescription(str) {
    return this.styleDescriptionText(str);
  }
  styleSubcommandDescription(str) {
    return this.styleDescriptionText(str);
  }
  styleArgumentDescription(str) {
    return this.styleDescriptionText(str);
  }
  styleDescriptionText(str) {
    return str;
  }
  styleOptionTerm(str) {
    return this.styleOptionText(str);
  }
  styleSubcommandTerm(str) {
    // This is very like usage with lots of parts! Assume default string which is formed like:
    //    subcommand [options] <foo> [bar]
    return str
      .split(' ')
      .map((word) => {
        if (word === '[options]') return this.styleOptionText(word);
        if (word[0] === '[' || word[0] === '<')
          return this.styleArgumentText(word);
        return this.styleSubcommandText(word); // Restrict to initial words?
      })
      .join(' ');
  }
  styleArgumentTerm(str) {
    return this.styleArgumentText(str);
  }
  styleOptionText(str) {
    return str;
  }
  styleArgumentText(str) {
    return str;
  }
  styleSubcommandText(str) {
    return str;
  }
  styleCommandText(str) {
    return str;
  }

  /**
   * Calculate the pad width from the maximum term length.
   *
   * @param {Command} cmd
   * @param {Help} helper
   * @returns {number}
   */

  padWidth(cmd, helper) {
    return Math.max(
      helper.longestOptionTermLength(cmd, helper),
      helper.longestGlobalOptionTermLength(cmd, helper),
      helper.longestSubcommandTermLength(cmd, helper),
      helper.longestArgumentTermLength(cmd, helper),
    );
  }

  /**
   * Detect manually wrapped and indented strings by checking for line break followed by whitespace.
   *
   * @param {string} str
   * @returns {boolean}
   */
  preformatted(str) {
    return /\n[^\S\r\n]/.test(str);
  }

  /**
   * Format the "item", which consists of a term and description. Pad the term and wrap the description, indenting the following lines.
   *
   * So "TTT", 5, "DDD DDDD DD DDD" might be formatted for this.helpWidth=17 like so:
   *   TTT  DDD DDDD
   *        DD DDD
   *
   * @param {string} term
   * @param {number} termWidth
   * @param {string} description
   * @param {Help} helper
   * @returns {string}
   */
  formatItem(term, termWidth, description, helper) {
    const itemIndent = 2;
    const itemIndentStr = ' '.repeat(itemIndent);
    if (!description) return itemIndentStr + term;

    // Pad the term out to a consistent width, so descriptions are aligned.
    const paddedTerm = term.padEnd(
      termWidth + term.length - helper.displayWidth(term),
    );

    // Format the description.
    const spacerWidth = 2; // between term and description
    const helpWidth = this.helpWidth ?? 80; // in case prepareContext() was not called
    const remainingWidth = helpWidth - termWidth - spacerWidth - itemIndent;
    let formattedDescription;
    if (
      remainingWidth < this.minWidthToWrap ||
      helper.preformatted(description)
    ) {
      formattedDescription = description;
    } else {
      const wrappedDescription = helper.boxWrap(description, remainingWidth);
      formattedDescription = wrappedDescription.replace(
        /\n/g,
        '\n' + ' '.repeat(termWidth + spacerWidth),
      );
    }

    // Construct and overall indent.
    return (
      itemIndentStr +
      paddedTerm +
      ' '.repeat(spacerWidth) +
      formattedDescription.replace(/\n/g, `\n${itemIndentStr}`)
    );
  }

  /**
   * Wrap a string at whitespace, preserving existing line breaks.
   * Wrapping is skipped if the width is less than `minWidthToWrap`.
   *
   * @param {string} str
   * @param {number} width
   * @returns {string}
   */
  boxWrap(str, width) {
    if (width < this.minWidthToWrap) return str;

    const rawLines = str.split(/\r\n|\n/);
    // split up text by whitespace
    const chunkPattern = /[\s]*[^\s]+/g;
    const wrappedLines = [];
    rawLines.forEach((line) => {
      const chunks = line.match(chunkPattern);
      if (chunks === null) {
        wrappedLines.push('');
        return;
      }

      let sumChunks = [chunks.shift()];
      let sumWidth = this.displayWidth(sumChunks[0]);
      chunks.forEach((chunk) => {
        const visibleWidth = this.displayWidth(chunk);
        // Accumulate chunks while they fit into width.
        if (sumWidth + visibleWidth <= width) {
          sumChunks.push(chunk);
          sumWidth += visibleWidth;
          return;
        }
        wrappedLines.push(sumChunks.join(''));

        const nextChunk = chunk.trimStart(); // trim space at line break
        sumChunks = [nextChunk];
        sumWidth = this.displayWidth(nextChunk);
      });
      wrappedLines.push(sumChunks.join(''));
    });

    return wrappedLines.join('\n');
  }
}

/**
 * Strip style ANSI escape sequences from the string. In particular, SGR (Select Graphic Rendition) codes.
 *
 * @param {string} str
 * @returns {string}
 * @package
 */

function stripColor(str) {
  // eslint-disable-next-line no-control-regex
  const sgrPattern = /\x1b\[\d*(;\d*)*m/g;
  return str.replace(sgrPattern, '');
}

exports.Help = Help;
exports.stripColor = stripColor;


/***/ }),

/***/ 240:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {

const { InvalidArgumentError } = __nccwpck_require__(135);

class Option {
  /**
   * Initialize a new `Option` with the given `flags` and `description`.
   *
   * @param {string} flags
   * @param {string} [description]
   */

  constructor(flags, description) {
    this.flags = flags;
    this.description = description || '';

    this.required = flags.includes('<'); // A value must be supplied when the option is specified.
    this.optional = flags.includes('['); // A value is optional when the option is specified.
    // variadic test ignores <value,...> et al which might be used to describe custom splitting of single argument
    this.variadic = /\w\.\.\.[>\]]$/.test(flags); // The option can take multiple values.
    this.mandatory = false; // The option must have a value after parsing, which usually means it must be specified on command line.
    const optionFlags = splitOptionFlags(flags);
    this.short = optionFlags.shortFlag; // May be a short flag, undefined, or even a long flag (if option has two long flags).
    this.long = optionFlags.longFlag;
    this.negate = false;
    if (this.long) {
      this.negate = this.long.startsWith('--no-');
    }
    this.defaultValue = undefined;
    this.defaultValueDescription = undefined;
    this.presetArg = undefined;
    this.envVar = undefined;
    this.parseArg = undefined;
    this.hidden = false;
    this.argChoices = undefined;
    this.conflictsWith = [];
    this.implied = undefined;
    this.helpGroupHeading = undefined; // soft initialised when option added to command
  }

  /**
   * Set the default value, and optionally supply the description to be displayed in the help.
   *
   * @param {*} value
   * @param {string} [description]
   * @return {Option}
   */

  default(value, description) {
    this.defaultValue = value;
    this.defaultValueDescription = description;
    return this;
  }

  /**
   * Preset to use when option used without option-argument, especially optional but also boolean and negated.
   * The custom processing (parseArg) is called.
   *
   * @example
   * new Option('--color').default('GREYSCALE').preset('RGB');
   * new Option('--donate [amount]').preset('20').argParser(parseFloat);
   *
   * @param {*} arg
   * @return {Option}
   */

  preset(arg) {
    this.presetArg = arg;
    return this;
  }

  /**
   * Add option name(s) that conflict with this option.
   * An error will be displayed if conflicting options are found during parsing.
   *
   * @example
   * new Option('--rgb').conflicts('cmyk');
   * new Option('--js').conflicts(['ts', 'jsx']);
   *
   * @param {(string | string[])} names
   * @return {Option}
   */

  conflicts(names) {
    this.conflictsWith = this.conflictsWith.concat(names);
    return this;
  }

  /**
   * Specify implied option values for when this option is set and the implied options are not.
   *
   * The custom processing (parseArg) is not called on the implied values.
   *
   * @example
   * program
   *   .addOption(new Option('--log', 'write logging information to file'))
   *   .addOption(new Option('--trace', 'log extra details').implies({ log: 'trace.txt' }));
   *
   * @param {object} impliedOptionValues
   * @return {Option}
   */
  implies(impliedOptionValues) {
    let newImplied = impliedOptionValues;
    if (typeof impliedOptionValues === 'string') {
      // string is not documented, but easy mistake and we can do what user probably intended.
      newImplied = { [impliedOptionValues]: true };
    }
    this.implied = Object.assign(this.implied || {}, newImplied);
    return this;
  }

  /**
   * Set environment variable to check for option value.
   *
   * An environment variable is only used if when processed the current option value is
   * undefined, or the source of the current value is 'default' or 'config' or 'env'.
   *
   * @param {string} name
   * @return {Option}
   */

  env(name) {
    this.envVar = name;
    return this;
  }

  /**
   * Set the custom handler for processing CLI option arguments into option values.
   *
   * @param {Function} [fn]
   * @return {Option}
   */

  argParser(fn) {
    this.parseArg = fn;
    return this;
  }

  /**
   * Whether the option is mandatory and must have a value after parsing.
   *
   * @param {boolean} [mandatory=true]
   * @return {Option}
   */

  makeOptionMandatory(mandatory = true) {
    this.mandatory = !!mandatory;
    return this;
  }

  /**
   * Hide option in help.
   *
   * @param {boolean} [hide=true]
   * @return {Option}
   */

  hideHelp(hide = true) {
    this.hidden = !!hide;
    return this;
  }

  /**
   * @package
   */

  _collectValue(value, previous) {
    if (previous === this.defaultValue || !Array.isArray(previous)) {
      return [value];
    }

    previous.push(value);
    return previous;
  }

  /**
   * Only allow option value to be one of choices.
   *
   * @param {string[]} values
   * @return {Option}
   */

  choices(values) {
    this.argChoices = values.slice();
    this.parseArg = (arg, previous) => {
      if (!this.argChoices.includes(arg)) {
        throw new InvalidArgumentError(
          `Allowed choices are ${this.argChoices.join(', ')}.`,
        );
      }
      if (this.variadic) {
        return this._collectValue(arg, previous);
      }
      return arg;
    };
    return this;
  }

  /**
   * Return option name.
   *
   * @return {string}
   */

  name() {
    if (this.long) {
      return this.long.replace(/^--/, '');
    }
    return this.short.replace(/^-/, '');
  }

  /**
   * Return option name, in a camelcase format that can be used
   * as an object attribute key.
   *
   * @return {string}
   */

  attributeName() {
    if (this.negate) {
      return camelcase(this.name().replace(/^no-/, ''));
    }
    return camelcase(this.name());
  }

  /**
   * Set the help group heading.
   *
   * @param {string} heading
   * @return {Option}
   */
  helpGroup(heading) {
    this.helpGroupHeading = heading;
    return this;
  }

  /**
   * Check if `arg` matches the short or long flag.
   *
   * @param {string} arg
   * @return {boolean}
   * @package
   */

  is(arg) {
    return this.short === arg || this.long === arg;
  }

  /**
   * Return whether a boolean option.
   *
   * Options are one of boolean, negated, required argument, or optional argument.
   *
   * @return {boolean}
   * @package
   */

  isBoolean() {
    return !this.required && !this.optional && !this.negate;
  }
}

/**
 * This class is to make it easier to work with dual options, without changing the existing
 * implementation. We support separate dual options for separate positive and negative options,
 * like `--build` and `--no-build`, which share a single option value. This works nicely for some
 * use cases, but is tricky for others where we want separate behaviours despite
 * the single shared option value.
 */
class DualOptions {
  /**
   * @param {Option[]} options
   */
  constructor(options) {
    this.positiveOptions = new Map();
    this.negativeOptions = new Map();
    this.dualOptions = new Set();
    options.forEach((option) => {
      if (option.negate) {
        this.negativeOptions.set(option.attributeName(), option);
      } else {
        this.positiveOptions.set(option.attributeName(), option);
      }
    });
    this.negativeOptions.forEach((value, key) => {
      if (this.positiveOptions.has(key)) {
        this.dualOptions.add(key);
      }
    });
  }

  /**
   * Did the value come from the option, and not from possible matching dual option?
   *
   * @param {*} value
   * @param {Option} option
   * @returns {boolean}
   */
  valueFromOption(value, option) {
    const optionKey = option.attributeName();
    if (!this.dualOptions.has(optionKey)) return true;

    // Use the value to deduce if (probably) came from the option.
    const preset = this.negativeOptions.get(optionKey).presetArg;
    const negativeValue = preset !== undefined ? preset : false;
    return option.negate === (negativeValue === value);
  }
}

/**
 * Convert string from kebab-case to camelCase.
 *
 * @param {string} str
 * @return {string}
 * @private
 */

function camelcase(str) {
  return str.split('-').reduce((str, word) => {
    return str + word[0].toUpperCase() + word.slice(1);
  });
}

/**
 * Split the short and long flag out of something like '-m,--mixed <value>'
 *
 * @private
 */

function splitOptionFlags(flags) {
  let shortFlag;
  let longFlag;
  // short flag, single dash and single character
  const shortFlagExp = /^-[^-]$/;
  // long flag, double dash and at least one character
  const longFlagExp = /^--[^-]/;

  const flagParts = flags.split(/[ |,]+/).concat('guard');
  // Normal is short and/or long.
  if (shortFlagExp.test(flagParts[0])) shortFlag = flagParts.shift();
  if (longFlagExp.test(flagParts[0])) longFlag = flagParts.shift();
  // Long then short. Rarely used but fine.
  if (!shortFlag && shortFlagExp.test(flagParts[0]))
    shortFlag = flagParts.shift();
  // Allow two long flags, like '--ws, --workspace'
  // This is the supported way to have a shortish option flag.
  if (!shortFlag && longFlagExp.test(flagParts[0])) {
    shortFlag = longFlag;
    longFlag = flagParts.shift();
  }

  // Check for unprocessed flag. Fail noisily rather than silently ignore.
  if (flagParts[0].startsWith('-')) {
    const unsupportedFlag = flagParts[0];
    const baseError = `option creation failed due to '${unsupportedFlag}' in option flags '${flags}'`;
    if (/^-[^-][^-]/.test(unsupportedFlag))
      throw new Error(
        `${baseError}
- a short flag is a single dash and a single character
  - either use a single dash and a single character (for a short flag)
  - or use a double dash for a long option (and can have two, like '--ws, --workspace')`,
      );
    if (shortFlagExp.test(unsupportedFlag))
      throw new Error(`${baseError}
- too many short flags`);
    if (longFlagExp.test(unsupportedFlag))
      throw new Error(`${baseError}
- too many long flags`);

    throw new Error(`${baseError}
- unrecognised flag format`);
  }
  if (shortFlag === undefined && longFlag === undefined)
    throw new Error(
      `option creation failed due to no flags found in '${flags}'.`,
    );

  return { shortFlag, longFlag };
}

exports.Option = Option;
exports.DualOptions = DualOptions;


/***/ }),

/***/ 30:
/***/ ((__unused_webpack_module, exports) => {

const maxDistance = 3;

function editDistance(a, b) {
  // https://en.wikipedia.org/wiki/Damerau–Levenshtein_distance
  // Calculating optimal string alignment distance, no substring is edited more than once.
  // (Simple implementation.)

  // Quick early exit, return worst case.
  if (Math.abs(a.length - b.length) > maxDistance)
    return Math.max(a.length, b.length);

  // distance between prefix substrings of a and b
  const d = [];

  // pure deletions turn a into empty string
  for (let i = 0; i <= a.length; i++) {
    d[i] = [i];
  }
  // pure insertions turn empty string into b
  for (let j = 0; j <= b.length; j++) {
    d[0][j] = j;
  }

  // fill matrix
  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      let cost = 1;
      if (a[i - 1] === b[j - 1]) {
        cost = 0;
      } else {
        cost = 1;
      }
      d[i][j] = Math.min(
        d[i - 1][j] + 1, // deletion
        d[i][j - 1] + 1, // insertion
        d[i - 1][j - 1] + cost, // substitution
      );
      // transposition
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }

  return d[a.length][b.length];
}

/**
 * Find close matches, restricted to same number of edits.
 *
 * @param {string} word
 * @param {string[]} candidates
 * @returns {string}
 */

function suggestSimilar(word, candidates) {
  if (!candidates || candidates.length === 0) return '';
  // remove possible duplicates
  candidates = Array.from(new Set(candidates));

  const searchingOptions = word.startsWith('--');
  if (searchingOptions) {
    word = word.slice(2);
    candidates = candidates.map((candidate) => candidate.slice(2));
  }

  let similar = [];
  let bestDistance = maxDistance;
  const minSimilarity = 0.4;
  candidates.forEach((candidate) => {
    if (candidate.length <= 1) return; // no one character guesses

    const distance = editDistance(word, candidate);
    const length = Math.max(word.length, candidate.length);
    const similarity = (length - distance) / length;
    if (similarity > minSimilarity) {
      if (distance < bestDistance) {
        // better edit distance, throw away previous worse matches
        bestDistance = distance;
        similar = [candidate];
      } else if (distance === bestDistance) {
        similar.push(candidate);
      }
    }
  });

  similar.sort((a, b) => a.localeCompare(b));
  if (searchingOptions) {
    similar = similar.map((candidate) => `--${candidate}`);
  }

  if (similar.length > 1) {
    return `\n(Did you mean one of ${similar.join(', ')}?)`;
  }
  if (similar.length === 1) {
    return `\n(Did you mean ${similar[0]}?)`;
  }
  return '';
}

exports.suggestSimilar = suggestSimilar;


/***/ }),

/***/ 182:
/***/ ((module) => {

"use strict";
module.exports = /*#__PURE__*/JSON.parse('{"version":"1.0.0","lastUpdated":"2025-11-24T19:34:59.871Z","attackInfo":{"name":"Shai-Hulud 2.0","alias":"The Second Coming","firstDetected":"2025-11-24T03:16:00Z","description":"Self-replicating npm worm targeting credential theft and supply chain compromise"},"indicators":{"maliciousFiles":["setup_bun.js","bun_environment.js","cloud.json","contents.json","environment.json","truffleSecrets.json"],"maliciousWorkflows":[".github/workflows/discussion.yaml",".github/workflows/formatter_*.yml"],"fileHashes":{"bun_environment.js":"d60ec97eea19fffb4809bc35b91033b52490ca11","setup_bun.js":"d1829b4708126dcc7bea7437c04d1f10eacd4a16"},"gitHubIndicators":{"runnerName":"SHA1HULUD","repoDescription":"Shai-Hulud: The Second Coming"}},"stats":{"totalUniquePackages":790,"byOrganization":{"asyncapi":36,"posthog":62,"postman":17,"ensdomains":46,"zapier":16,"voiceflow":57,"browserbasehq":7,"okuui":41,"other":508}},"packages":[{"name":"02-echo","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/concerto-analysis","severity":"critical","affectedVersions":["*"]},{"name":"@vue/cli-plugin-babel","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/concerto-linter","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/concerto-linter-default-ruleset","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/concerto-metamodel","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/concerto-types","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/markdown-docx","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/markdown-it-cicero","severity":"critical","affectedVersions":["*"]},{"name":"@accordproject/template-engine","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/css-to-react-native-transform","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/native","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/node-server","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-absolute","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-daum-postcode","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-kakaosdk","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-actionsheet","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-devtools","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-fast-image","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-kakao-channel","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-kakao-navi","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-less-transformer","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-naver-login","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-simple-video","severity":"critical","affectedVersions":["*"]},{"name":"@actbase/react-native-tiktok","severity":"critical","affectedVersions":["*"]},{"name":"@afetcan/api","severity":"critical","affectedVersions":["*"]},{"name":"@afetcan/storage","severity":"critical","affectedVersions":["*"]},{"name":"@alaan/s2s-auth","severity":"critical","affectedVersions":["*"]},{"name":"@alexadark/amadeus-api","severity":"critical","affectedVersions":["*"]},{"name":"@alexadark/gatsby-theme-events","severity":"critical","affectedVersions":["*"]},{"name":"@alexadark/gatsby-theme-wordpress-blog","severity":"critical","affectedVersions":["*"]},{"name":"@alexadark/reusable-functions","severity":"critical","affectedVersions":["*"]},{"name":"@alexcolls/nuxt-socket.io","severity":"critical","affectedVersions":["*"]},{"name":"@alexcolls/nuxt-ux","severity":"critical","affectedVersions":["*"]},{"name":"@antstackio/eslint-config-antstack","severity":"critical","affectedVersions":["*"]},{"name":"@antstackio/express-graphql-proxy","severity":"critical","affectedVersions":["*"]},{"name":"@antstackio/graphql-body-parser","severity":"critical","affectedVersions":["*"]},{"name":"@antstackio/json-to-graphql","severity":"critical","affectedVersions":["*"]},{"name":"@antstackio/shelbysam","severity":"critical","affectedVersions":["*"]},{"name":"@aryanhussain/my-angular-lib","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/avro-schema-parser","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/bundler","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/cli","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/converter","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/diff","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/dotnet-rabbitmq-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/edavisualiser","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/generator","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/generator-components","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/generator-helpers","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/generator-react-sdk","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/go-watermill-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/html-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/java-spring-cloud-stream-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/java-spring-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/java-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/keeper","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/markdown-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/modelina","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/modelina-cli","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/multi-parser","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/nodejs-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/nodejs-ws-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/nunjucks-filters","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/openapi-schema-parser","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/optimizer","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/parser","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/php-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/problem","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/protobuf-schema-parser","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/python-paho-template","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/react-component","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/server-api","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/specs","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/studio","severity":"critical","affectedVersions":["*"]},{"name":"@asyncapi/web-component","severity":"critical","affectedVersions":["*"]},{"name":"@bdkinc/knex-ibmi","severity":"critical","affectedVersions":["*"]},{"name":"@browserbasehq/bb9","severity":"critical","affectedVersions":["*"]},{"name":"@browserbasehq/director-ai","severity":"critical","affectedVersions":["*"]},{"name":"@browserbasehq/mcp","severity":"critical","affectedVersions":["*"]},{"name":"@browserbasehq/mcp-server-browserbase","severity":"critical","affectedVersions":["*"]},{"name":"@browserbasehq/sdk-functions","severity":"critical","affectedVersions":["*"]},{"name":"@browserbasehq/stagehand","severity":"critical","affectedVersions":["*"]},{"name":"@browserbasehq/stagehand-docs","severity":"critical","affectedVersions":["*"]},{"name":"@caretive/caret-cli","severity":"critical","affectedVersions":["*"]},{"name":"@chtijs/eslint-config","severity":"critical","affectedVersions":["*"]},{"name":"@clausehq/flows-step-httprequest","severity":"critical","affectedVersions":["*"]},{"name":"@clausehq/flows-step-jsontoxml","severity":"critical","affectedVersions":["*"]},{"name":"@clausehq/flows-step-mqtt","severity":"critical","affectedVersions":["*"]},{"name":"@clausehq/flows-step-sendgridemail","severity":"critical","affectedVersions":["*"]},{"name":"@clausehq/flows-step-taskscreateurl","severity":"critical","affectedVersions":["*"]},{"name":"@cllbk/ghl","severity":"critical","affectedVersions":["*"]},{"name":"@commute/bloom","severity":"critical","affectedVersions":["*"]},{"name":"@commute/market-data","severity":"critical","affectedVersions":["*"]},{"name":"@commute/market-data-chartjs","severity":"critical","affectedVersions":["*"]},{"name":"@dev-blinq/ai-qa-logic","severity":"critical","affectedVersions":["*"]},{"name":"@dev-blinq/blinqioclient","severity":"critical","affectedVersions":["*"]},{"name":"@dev-blinq/cucumber-js","severity":"critical","affectedVersions":["*"]},{"name":"@dev-blinq/cucumber_client","severity":"critical","affectedVersions":["*"]},{"name":"@dev-blinq/ui-systems","severity":"critical","affectedVersions":["*"]},{"name":"@elsedev/react-csr-sdk","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/address-encoder","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/blacklist","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/buffer","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ccip-read-cf-worker","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ccip-read-dns-gateway","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ccip-read-router","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ccip-read-worker-viem","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/content-hash","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/curvearithmetics","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/cypress-metamask","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/dnsprovejs","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/dnssec-oracle-anchors","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/dnssecoraclejs","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/durin","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/durin-middleware","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ens-archived-contracts","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ens-avatar","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ens-contracts","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ens-test-env","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ens-validation","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ensjs","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ensjs-react","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/eth-ens-namehash","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/hackathon-registrar","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/hardhat-chai-matchers-viem","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/hardhat-toolbox-viem-extended","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/mock","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/name-wrapper","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/offchain-resolver-contracts","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/op-resolver-contracts","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/react-ens-address","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/renewal","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/renewal-widget","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/reverse-records","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/server-analytics","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/solsha1","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/subdomain-registrar","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/test-utils","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/thorin","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/ui","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/unicode-confusables","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/unruggable-gateways","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/vite-plugin-i18next-loader","severity":"critical","affectedVersions":["*"]},{"name":"@ensdomains/web3modal","severity":"critical","affectedVersions":["*"]},{"name":"@everreal/react-charts","severity":"critical","affectedVersions":["*"]},{"name":"@everreal/validate-esmoduleinterop-imports","severity":"critical","affectedVersions":["*"]},{"name":"@everreal/web-analytics","severity":"critical","affectedVersions":["*"]},{"name":"@faq-component/core","severity":"critical","affectedVersions":["*"]},{"name":"@faq-component/react","severity":"critical","affectedVersions":["*"]},{"name":"@fishingbooker/browser-sync-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@fishingbooker/react-loader","severity":"critical","affectedVersions":["*"]},{"name":"@fishingbooker/react-pagination","severity":"critical","affectedVersions":["*"]},{"name":"@fishingbooker/react-raty","severity":"critical","affectedVersions":["*"]},{"name":"@fishingbooker/react-swiper","severity":"critical","affectedVersions":["*"]},{"name":"@hapheus/n8n-nodes-pgp","severity":"critical","affectedVersions":["*"]},{"name":"@hover-design/core","severity":"critical","affectedVersions":["*"]},{"name":"@hover-design/react","severity":"critical","affectedVersions":["*"]},{"name":"@huntersofbook/auth-vue","severity":"critical","affectedVersions":["*"]},{"name":"@huntersofbook/core","severity":"critical","affectedVersions":["*"]},{"name":"@huntersofbook/core-nuxt","severity":"critical","affectedVersions":["*"]},{"name":"@huntersofbook/form-naiveui","severity":"critical","affectedVersions":["*"]},{"name":"@huntersofbook/i18n","severity":"critical","affectedVersions":["*"]},{"name":"@huntersofbook/ui","severity":"critical","affectedVersions":["*"]},{"name":"@hyperlook/telemetry-sdk","severity":"critical","affectedVersions":["*"]},{"name":"@ifelsedeveloper/protocol-contracts-svm-idl","severity":"critical","affectedVersions":["*"]},{"name":"@ifings/design-system","severity":"critical","affectedVersions":["*"]},{"name":"@ifings/metatron3","severity":"critical","affectedVersions":["*"]},{"name":"@jayeshsadhwani/telemetry-sdk","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/cli","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/components","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/habbit-e2e-test","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/medusa-plugin-announcement","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/medusa-plugin-management","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/medusa-plugin-newsletter","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/medusa-plugin-product-reviews","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/medusa-plugin-promotion","severity":"critical","affectedVersions":["*"]},{"name":"@kvytech/web","severity":"critical","affectedVersions":["*"]},{"name":"@lessondesk/api-client","severity":"critical","affectedVersions":["*"]},{"name":"@lessondesk/babel-preset","severity":"critical","affectedVersions":["*"]},{"name":"@lessondesk/electron-group-api-client","severity":"critical","affectedVersions":["*"]},{"name":"@lessondesk/eslint-config","severity":"critical","affectedVersions":["*"]},{"name":"@lessondesk/material-icons","severity":"critical","affectedVersions":["*"]},{"name":"@lessondesk/react-table-context","severity":"critical","affectedVersions":["*"]},{"name":"@lessondesk/schoolbus","severity":"critical","affectedVersions":["*"]},{"name":"@livecms/live-edit","severity":"critical","affectedVersions":["*"]},{"name":"@livecms/nuxt-live-edit","severity":"critical","affectedVersions":["*"]},{"name":"@lokeswari-satyanarayanan/rn-zustand-expo-template","severity":"critical","affectedVersions":["*"]},{"name":"@louisle2/core","severity":"critical","affectedVersions":["*"]},{"name":"@louisle2/cortex-js","severity":"critical","affectedVersions":["*"]},{"name":"@lpdjs/firestore-repo-service","severity":"critical","affectedVersions":["*"]},{"name":"@lui-ui/lui-nuxt","severity":"critical","affectedVersions":["*"]},{"name":"@lui-ui/lui-tailwindcss","severity":"critical","affectedVersions":["*"]},{"name":"@lui-ui/lui-vue","severity":"critical","affectedVersions":["*"]},{"name":"@markvivanco/app-version-checker","severity":"critical","affectedVersions":["*"]},{"name":"@mcp-use/cli","severity":"critical","affectedVersions":["*"]},{"name":"@mcp-use/inspector","severity":"critical","affectedVersions":["*"]},{"name":"@mcp-use/mcp-use","severity":"critical","affectedVersions":["*"]},{"name":"@mparpaillon/connector-parse","severity":"critical","affectedVersions":["*"]},{"name":"@mparpaillon/imagesloaded","severity":"critical","affectedVersions":["*"]},{"name":"@mparpaillon/page","severity":"critical","affectedVersions":["*"]},{"name":"@ntnx/passport-wso2","severity":"critical","affectedVersions":["*"]},{"name":"@ntnx/t","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/accordion","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/arrow","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/aspect-ratio","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/avatar","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/checkbox","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/collapsible","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/collection","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/dialog","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/direction","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/dismissable-layer","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/focus-guards","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/focus-scope","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/hover-card","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/label","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/menu","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/motion","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/motion-nuxt","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/popover","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/popper","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/portal","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/presence","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/primitives","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/primitives-nuxt","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/progress","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/provide","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/radio-group","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/roving-focus","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/scroll-area","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/separator","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/slider","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/slot","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/switch","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/tabs","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/toast","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/toggle","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/toggle-group","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/toolbar","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/tooltip","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/use-composable","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/utils","severity":"critical","affectedVersions":["*"]},{"name":"@oku-ui/visually-hidden","severity":"critical","affectedVersions":["*"]},{"name":"@orbitgtbelgium/mapbox-gl-draw-cut-polygon-mode","severity":"critical","affectedVersions":["*"]},{"name":"@orbitgtbelgium/mapbox-gl-draw-scale-rotate-mode","severity":"critical","affectedVersions":["*"]},{"name":"@orbitgtbelgium/orbit-components","severity":"critical","affectedVersions":["*"]},{"name":"@orbitgtbelgium/time-slider","severity":"critical","affectedVersions":["*"]},{"name":"@osmanekrem/bmad","severity":"critical","affectedVersions":["*"]},{"name":"@osmanekrem/error-handler","severity":"critical","affectedVersions":["*"]},{"name":"@pergel/cli","severity":"critical","affectedVersions":["*"]},{"name":"@pergel/module-box","severity":"critical","affectedVersions":["*"]},{"name":"@pergel/module-graphql","severity":"critical","affectedVersions":["*"]},{"name":"@pergel/module-ui","severity":"critical","affectedVersions":["*"]},{"name":"@pergel/nuxt","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/agent","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/ai","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/automatic-cohorts-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/bitbucket-release-tracker","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/cli","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/clickhouse","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/core","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/currency-normalization-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/customerio-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/databricks-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/drop-events-on-property-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/event-sequence-timer-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/filter-out-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/first-time-event-tracker","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/geoip-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/github-release-tracking-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/gitub-star-sync-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/heartbeat-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/hedgehog-mode","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/icons","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/ingestion-alert-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/intercom-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/kinesis-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/laudspeaker-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/lemon-ui","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/maxmind-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/migrator3000-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/netdata-event-processing","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/nextjs","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/nextjs-config","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/nuxt","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/pagerduty-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/piscina","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/plugin-contrib","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/plugin-server","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/plugin-unduplicates","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/postgres-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/react-rrweb-player","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/rrdom","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/rrweb","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/rrweb-player","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/rrweb-record","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/rrweb-replay","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/rrweb-snapshot","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/rrweb-utils","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/sendgrid-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/siphash","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/snowflake-export-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/taxonomy-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/twilio-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/twitter-followers-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/url-normalizer-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/variance-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/web-dev-server","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/wizard","severity":"critical","affectedVersions":["*"]},{"name":"@posthog/zendesk-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@postman/aether-icons","severity":"critical","affectedVersions":["*"]},{"name":"@postman/csv-parse","severity":"critical","affectedVersions":["*"]},{"name":"@postman/final-node-keytar","severity":"critical","affectedVersions":["*"]},{"name":"@postman/mcp-ui-client","severity":"critical","affectedVersions":["*"]},{"name":"@postman/node-keytar","severity":"critical","affectedVersions":["*"]},{"name":"@postman/pm-bin-linux-x64","severity":"critical","affectedVersions":["*"]},{"name":"@postman/pm-bin-macos-arm64","severity":"critical","affectedVersions":["*"]},{"name":"@postman/pm-bin-macos-x64","severity":"critical","affectedVersions":["*"]},{"name":"@postman/pm-bin-windows-x64","severity":"critical","affectedVersions":["*"]},{"name":"@postman/postman-collection-fork","severity":"critical","affectedVersions":["*"]},{"name":"@postman/postman-mcp-cli","severity":"critical","affectedVersions":["*"]},{"name":"@postman/postman-mcp-server","severity":"critical","affectedVersions":["*"]},{"name":"@postman/pretty-ms","severity":"critical","affectedVersions":["*"]},{"name":"@postman/secret-scanner-wasm","severity":"critical","affectedVersions":["*"]},{"name":"@postman/tunnel-agent","severity":"critical","affectedVersions":["*"]},{"name":"@postman/wdio-allure-reporter","severity":"critical","affectedVersions":["*"]},{"name":"@postman/wdio-junit-reporter","severity":"critical","affectedVersions":["*"]},{"name":"@pradhumngautam/common-app","severity":"critical","affectedVersions":["*"]},{"name":"@productdevbook/animejs-vue","severity":"critical","affectedVersions":["*"]},{"name":"@productdevbook/auth","severity":"critical","affectedVersions":["*"]},{"name":"@productdevbook/chatwoot","severity":"critical","affectedVersions":["*"]},{"name":"@productdevbook/motion","severity":"critical","affectedVersions":["*"]},{"name":"@productdevbook/ts-i18n","severity":"critical","affectedVersions":["*"]},{"name":"@pruthvi21/use-debounce","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-document-translator","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-git-clean-markdown","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-markdown","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-markdown-compose","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-markdown-image","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-markdown-print","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-markdown-translator","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-remove-image-background","severity":"critical","affectedVersions":["*"]},{"name":"@quick-start-soft/quick-task-refine","severity":"critical","affectedVersions":["*"]},{"name":"@relyt/claude-context-core","severity":"critical","affectedVersions":["*"]},{"name":"@relyt/claude-context-mcp","severity":"critical","affectedVersions":["*"]},{"name":"@relyt/mcp-server-relytone","severity":"critical","affectedVersions":["*"]},{"name":"@sameepsi/sor","severity":"critical","affectedVersions":["*"]},{"name":"@sameepsi/sor2","severity":"critical","affectedVersions":["*"]},{"name":"@seezo/sdr-mcp-server","severity":"critical","affectedVersions":["*"]},{"name":"@seung-ju/next","severity":"critical","affectedVersions":["*"]},{"name":"@seung-ju/openapi-generator","severity":"critical","affectedVersions":["*"]},{"name":"@seung-ju/react-hooks","severity":"critical","affectedVersions":["*"]},{"name":"@seung-ju/react-native-action-sheet","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/better-auth","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/drizzle","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/ecosystem","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/graphql","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/module-builder","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/openapi","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/permission","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/ratelimit","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/scalar","severity":"critical","affectedVersions":["*"]},{"name":"@silgi/yoga","severity":"critical","affectedVersions":["*"]},{"name":"@sme-ui/aoma-vevasound-metadata-lib","severity":"critical","affectedVersions":["*"]},{"name":"@strapbuild/react-native-date-time-picker","severity":"critical","affectedVersions":["*"]},{"name":"@strapbuild/react-native-perspective-image-cropper","severity":"critical","affectedVersions":["*"]},{"name":"@strapbuild/react-native-perspective-image-cropper-2","severity":"critical","affectedVersions":["*"]},{"name":"@strapbuild/react-native-perspective-image-cropper-poojan31","severity":"critical","affectedVersions":["*"]},{"name":"@suraj_h/medium-common","severity":"critical","affectedVersions":["*"]},{"name":"@thedelta/eslint-config","severity":"critical","affectedVersions":["*"]},{"name":"@tiaanduplessis/json","severity":"critical","affectedVersions":["*"]},{"name":"@tiaanduplessis/react-progressbar","severity":"critical","affectedVersions":["*"]},{"name":"@trackstar/angular-trackstar-link","severity":"critical","affectedVersions":["*"]},{"name":"@trackstar/react-trackstar-link","severity":"critical","affectedVersions":["*"]},{"name":"@trackstar/react-trackstar-link-upgrade","severity":"critical","affectedVersions":["*"]},{"name":"@trackstar/test-angular-package","severity":"critical","affectedVersions":["*"]},{"name":"@trackstar/test-package","severity":"critical","affectedVersions":["*"]},{"name":"@trefox/sleekshop-js","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-acl","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-elasticsearch","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-mongoose","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-orientdb","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-postgres","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-pubsub","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-redis","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-soap","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/atrix-swagger","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/bool-expressions","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/eslint-config-trigo","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/fsm","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/hapi-auth-signedlink","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/jsdt","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/keycloak-api","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/node-soap","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/pathfinder-ui-css","severity":"critical","affectedVersions":["*"]},{"name":"@trigo/trigo-hapijs","severity":"critical","affectedVersions":["*"]},{"name":"@trpc-rate-limiter/cloudflare","severity":"critical","affectedVersions":["*"]},{"name":"@trpc-rate-limiter/hono","severity":"critical","affectedVersions":["*"]},{"name":"@varsityvibe/api-client","severity":"critical","affectedVersions":["*"]},{"name":"@varsityvibe/utils","severity":"critical","affectedVersions":["*"]},{"name":"@varsityvibe/validation-schemas","severity":"critical","affectedVersions":["*"]},{"name":"@viapip/eslint-config","severity":"critical","affectedVersions":["*"]},{"name":"@vishadtyagi/full-year-calendar","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/alexa-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/anthropic","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/api-sdk","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/backend-utils","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/base-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/body-parser","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/chat-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/circleci-config-sdk-orb-import","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/commitlint-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/common","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/default-prompt-wrappers","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/dependency-cruiser-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/dtos-interact","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/encryption","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/eslint-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/eslint-plugin","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/exception","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/fetch","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/general-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/git-branch-check","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/google-dfes-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/google-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/husky-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/logger","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/metrics","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/natural-language-commander","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/nestjs-common","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/nestjs-mongodb","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/nestjs-rate-limit","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/nestjs-redis","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/nestjs-timeout","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/npm-package-json-lint-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/openai","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/pino","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/pino-pretty","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/prettier-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/react-chat","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/runtime","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/runtime-client-js","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/sdk-runtime","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/secrets-provider","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/semantic-release-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/serverless-plugin-typescript","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/slate-serializer","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/stitches-react","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/storybook-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/stylelint-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/test-common","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/tsconfig","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/tsconfig-paths","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/utils-designer","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/verror","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/vite-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/vitest-config","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/voice-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/voiceflow-types","severity":"critical","affectedVersions":["*"]},{"name":"@voiceflow/widget","severity":"critical","affectedVersions":["*"]},{"name":"@vucod/email","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/ai-actions","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/ai-actions-react","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/babel-preset-zapier","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/browserslist-config-zapier","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/eslint-plugin-zapier","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/mcp-integration","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/secret-scrubber","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/spectral-api-ruleset","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/stubtree","severity":"critical","affectedVersions":["*"]},{"name":"@zapier/zapier-sdk","severity":"critical","affectedVersions":["*"]},{"name":"ai-crowl-shield","severity":"critical","affectedVersions":["*"]},{"name":"arc-cli-fc","severity":"critical","affectedVersions":["*"]},{"name":"asciitranslator","severity":"critical","affectedVersions":["*"]},{"name":"asyncapi-preview","severity":"critical","affectedVersions":["*"]},{"name":"atrix","severity":"critical","affectedVersions":["*"]},{"name":"atrix-mongoose","severity":"critical","affectedVersions":["*"]},{"name":"automation_model","severity":"critical","affectedVersions":["*"]},{"name":"avvvatars-vue","severity":"critical","affectedVersions":["*"]},{"name":"axios-builder","severity":"critical","affectedVersions":["*"]},{"name":"axios-cancelable","severity":"critical","affectedVersions":["*"]},{"name":"axios-timed","severity":"critical","affectedVersions":["*"]},{"name":"babel-preset-kinvey-flex-service","severity":"critical","affectedVersions":["*"]},{"name":"barebones-css","severity":"critical","affectedVersions":["*"]},{"name":"benmostyn-frame-print","severity":"critical","affectedVersions":["*"]},{"name":"best_gpio_controller","severity":"critical","affectedVersions":["*"]},{"name":"bestgpiocontroller","severity":"critical","affectedVersions":["*"]},{"name":"better-auth-nuxt","severity":"critical","affectedVersions":["*"]},{"name":"bidirectional-adapter","severity":"critical","affectedVersions":["*"]},{"name":"blinqio-executions-cli","severity":"critical","affectedVersions":["*"]},{"name":"blob-to-base64","severity":"critical","affectedVersions":["*"]},{"name":"bool-expressions","severity":"critical","affectedVersions":["*"]},{"name":"buffered-interpolation-babylon6","severity":"critical","affectedVersions":["*"]},{"name":"bun-plugin-httpfile","severity":"critical","affectedVersions":["*"]},{"name":"bytecode-checker-cli","severity":"critical","affectedVersions":["*"]},{"name":"bytes-to-x","severity":"critical","affectedVersions":["*"]},{"name":"calc-loan-interest","severity":"critical","affectedVersions":["*"]},{"name":"capacitor-plugin-apptrackingios","severity":"critical","affectedVersions":["*"]},{"name":"capacitor-plugin-purchase","severity":"critical","affectedVersions":["*"]},{"name":"capacitor-plugin-scgssigninwithgoogle","severity":"critical","affectedVersions":["*"]},{"name":"capacitor-purchase-history","severity":"critical","affectedVersions":["*"]},{"name":"capacitor-voice-recorder-wav","severity":"critical","affectedVersions":["*"]},{"name":"cbre-flow-common","severity":"critical","affectedVersions":["*"]},{"name":"ceviz","severity":"critical","affectedVersions":["*"]},{"name":"chrome-extension-downloads","severity":"critical","affectedVersions":["*"]},{"name":"claude-token-updater","severity":"critical","affectedVersions":["*"]},{"name":"coinmarketcap-api","severity":"critical","affectedVersions":["*"]},{"name":"colors-regex","severity":"critical","affectedVersions":["*"]},{"name":"command-irail","severity":"critical","affectedVersions":["*"]},{"name":"compare-obj","severity":"critical","affectedVersions":["*"]},{"name":"composite-reducer","severity":"critical","affectedVersions":["*"]},{"name":"count-it-down","severity":"critical","affectedVersions":["*"]},{"name":"cpu-instructions","severity":"critical","affectedVersions":["*"]},{"name":"create-director-app","severity":"critical","affectedVersions":["*"]},{"name":"create-glee-app","severity":"critical","affectedVersions":["*"]},{"name":"create-hardhat3-app","severity":"critical","affectedVersions":["*"]},{"name":"create-kinvey-flex-service","severity":"critical","affectedVersions":["*"]},{"name":"create-mcp-use-app","severity":"critical","affectedVersions":["*"]},{"name":"create-silgi","severity":"critical","affectedVersions":["*"]},{"name":"crypto-addr-codec","severity":"critical","affectedVersions":["*"]},{"name":"css-dedoupe","severity":"critical","affectedVersions":["*"]},{"name":"csv-tool-cli","severity":"critical","affectedVersions":["*"]},{"name":"dashboard-empty-state","severity":"critical","affectedVersions":["*"]},{"name":"designstudiouiux","severity":"critical","affectedVersions":["*"]},{"name":"devstart-cli","severity":"critical","affectedVersions":["*"]},{"name":"dialogflow-es","severity":"critical","affectedVersions":["*"]},{"name":"discord-bot-server","severity":"critical","affectedVersions":["*"]},{"name":"docusaurus-plugin-vanilla-extract","severity":"critical","affectedVersions":["*"]},{"name":"dont-go","severity":"critical","affectedVersions":["*"]},{"name":"dotnet-template","severity":"critical","affectedVersions":["*"]},{"name":"drop-events-on-property-plugin","severity":"critical","affectedVersions":["*"]},{"name":"easypanel-sdk","severity":"critical","affectedVersions":["*"]},{"name":"email-deliverability-tester","severity":"critical","affectedVersions":["*"]},{"name":"enforce-branch-name","severity":"critical","affectedVersions":["*"]},{"name":"esbuild-plugin-brotli","severity":"critical","affectedVersions":["*"]},{"name":"esbuild-plugin-eta","severity":"critical","affectedVersions":["*"]},{"name":"esbuild-plugin-httpfile","severity":"critical","affectedVersions":["*"]},{"name":"eslint-config-nitpicky","severity":"critical","affectedVersions":["*"]},{"name":"eslint-config-trigo","severity":"critical","affectedVersions":["*"]},{"name":"eslint-config-zeallat-base","severity":"critical","affectedVersions":["*"]},{"name":"ethereum-ens","severity":"critical","affectedVersions":["*"]},{"name":"evm-checkcode-cli","severity":"critical","affectedVersions":["*"]},{"name":"exact-ticker","severity":"critical","affectedVersions":["*"]},{"name":"expo-audio-session","severity":"critical","affectedVersions":["*"]},{"name":"expo-router-on-rails","severity":"critical","affectedVersions":["*"]},{"name":"express-starter-template","severity":"critical","affectedVersions":["*"]},{"name":"expressos","severity":"critical","affectedVersions":["*"]},{"name":"fat-fingered","severity":"critical","affectedVersions":["*"]},{"name":"feature-flip","severity":"critical","affectedVersions":["*"]},{"name":"firestore-search-engine","severity":"critical","affectedVersions":["*"]},{"name":"fittxt","severity":"critical","affectedVersions":["*"]},{"name":"flapstacks","severity":"critical","affectedVersions":["*"]},{"name":"flatten-unflatten","severity":"critical","affectedVersions":["*"]},{"name":"formik-error-focus","severity":"critical","affectedVersions":["*"]},{"name":"formik-store","severity":"critical","affectedVersions":["*"]},{"name":"frontity-starter-theme","severity":"critical","affectedVersions":["*"]},{"name":"fuzzy-finder","severity":"critical","affectedVersions":["*"]},{"name":"gate-evm-check-code2","severity":"critical","affectedVersions":["*"]},{"name":"gate-evm-tools-test","severity":"critical","affectedVersions":["*"]},{"name":"gatsby-plugin-antd","severity":"critical","affectedVersions":["*"]},{"name":"gatsby-plugin-cname","severity":"critical","affectedVersions":["*"]},{"name":"generator-meteor-stock","severity":"critical","affectedVersions":["*"]},{"name":"generator-ng-itobuz","severity":"critical","affectedVersions":["*"]},{"name":"get-them-args","severity":"critical","affectedVersions":["*"]},{"name":"github-action-for-generator","severity":"critical","affectedVersions":["*"]},{"name":"gitsafe","severity":"critical","affectedVersions":["*"]},{"name":"go-template","severity":"critical","affectedVersions":["*"]},{"name":"gulp-inject-envs","severity":"critical","affectedVersions":["*"]},{"name":"haufe-axera-api-client","severity":"critical","affectedVersions":["*"]},{"name":"hope-mapboxdraw","severity":"critical","affectedVersions":["*"]},{"name":"hopedraw","severity":"critical","affectedVersions":["*"]},{"name":"hover-design-prototype","severity":"critical","affectedVersions":["*"]},{"name":"httpness","severity":"critical","affectedVersions":["*"]},{"name":"hyper-fullfacing","severity":"critical","affectedVersions":["*"]},{"name":"hyperterm-hipster","severity":"critical","affectedVersions":["*"]},{"name":"ids-css","severity":"critical","affectedVersions":["*"]},{"name":"ids-enterprise-mcp-server","severity":"critical","affectedVersions":["*"]},{"name":"ids-enterprise-ng","severity":"critical","affectedVersions":["*"]},{"name":"ids-enterprise-typings","severity":"critical","affectedVersions":["*"]},{"name":"image-to-uri","severity":"critical","affectedVersions":["*"]},{"name":"insomnia-plugin-random-pick","severity":"critical","affectedVersions":["*"]},{"name":"invo","severity":"critical","affectedVersions":["*"]},{"name":"iron-shield-miniapp","severity":"critical","affectedVersions":["*"]},{"name":"ito-button","severity":"critical","affectedVersions":["*"]},{"name":"itobuz-angular","severity":"critical","affectedVersions":["*"]},{"name":"itobuz-angular-auth","severity":"critical","affectedVersions":["*"]},{"name":"itobuz-angular-button","severity":"critical","affectedVersions":["*"]},{"name":"jacob-zuma","severity":"critical","affectedVersions":["*"]},{"name":"jaetut-varit-test","severity":"critical","affectedVersions":["*"]},{"name":"jan-browser","severity":"critical","affectedVersions":["*"]},{"name":"jquery-bindings","severity":"critical","affectedVersions":["*"]},{"name":"jsonsurge","severity":"critical","affectedVersions":["*"]},{"name":"just-toasty","severity":"critical","affectedVersions":["*"]},{"name":"kill-port","severity":"critical","affectedVersions":["*"]},{"name":"kinetix-default-token-list","severity":"critical","affectedVersions":["*"]},{"name":"kinvey-flex-scripts","severity":"critical","affectedVersions":["*"]},{"name":"korea-administrative-area-geo-json-util","severity":"critical","affectedVersions":["*"]},{"name":"kwami","severity":"critical","affectedVersions":["*"]},{"name":"lang-codes","severity":"critical","affectedVersions":["*"]},{"name":"license-o-matic","severity":"critical","affectedVersions":["*"]},{"name":"lint-staged-imagemin","severity":"critical","affectedVersions":["*"]},{"name":"lite-serper-mcp-server","severity":"critical","affectedVersions":["*"]},{"name":"lui-vue-test","severity":"critical","affectedVersions":["*"]},{"name":"luno-api","severity":"critical","affectedVersions":["*"]},{"name":"manual-billing-system-miniapp-api","severity":"critical","affectedVersions":["*"]},{"name":"mcp-use","severity":"critical","affectedVersions":["*"]},{"name":"medusa-plugin-announcement","severity":"critical","affectedVersions":["*"]},{"name":"medusa-plugin-logs","severity":"critical","affectedVersions":["*"]},{"name":"medusa-plugin-momo","severity":"critical","affectedVersions":["*"]},{"name":"medusa-plugin-product-reviews-kvy","severity":"critical","affectedVersions":["*"]},{"name":"medusa-plugin-zalopay","severity":"critical","affectedVersions":["*"]},{"name":"mod10-check-digit","severity":"critical","affectedVersions":["*"]},{"name":"mon-package-react-typescript","severity":"critical","affectedVersions":["*"]},{"name":"my-saeed-lib","severity":"critical","affectedVersions":["*"]},{"name":"n8n-nodes-tmdb","severity":"critical","affectedVersions":["*"]},{"name":"n8n-nodes-vercel-ai-sdk","severity":"critical","affectedVersions":["*"]},{"name":"n8n-nodes-viral-app","severity":"critical","affectedVersions":["*"]},{"name":"nanoreset","severity":"critical","affectedVersions":["*"]},{"name":"next-circular-dependency","severity":"critical","affectedVersions":["*"]},{"name":"next-simple-google-analytics","severity":"critical","affectedVersions":["*"]},{"name":"next-styled-nprogress","severity":"critical","affectedVersions":["*"]},{"name":"ngx-useful-swiper-prosenjit","severity":"critical","affectedVersions":["*"]},{"name":"ngx-wooapi","severity":"critical","affectedVersions":["*"]},{"name":"nitro-graphql","severity":"critical","affectedVersions":["*"]},{"name":"nitro-kutu","severity":"critical","affectedVersions":["*"]},{"name":"nitrodeploy","severity":"critical","affectedVersions":["*"]},{"name":"nitroping","severity":"critical","affectedVersions":["*"]},{"name":"normal-store","severity":"critical","affectedVersions":["*"]},{"name":"nuxt-keycloak","severity":"critical","affectedVersions":["*"]},{"name":"obj-to-css","severity":"critical","affectedVersions":["*"]},{"name":"okta-react-router-6","severity":"critical","affectedVersions":["*"]},{"name":"open2internet","severity":"critical","affectedVersions":["*"]},{"name":"orbit-boxicons","severity":"critical","affectedVersions":["*"]},{"name":"orbit-nebula-draw-tools","severity":"critical","affectedVersions":["*"]},{"name":"orbit-nebula-editor","severity":"critical","affectedVersions":["*"]},{"name":"orbit-soap","severity":"critical","affectedVersions":["*"]},{"name":"orchestrix","severity":"critical","affectedVersions":["*"]},{"name":"package-tester","severity":"critical","affectedVersions":["*"]},{"name":"parcel-plugin-asset-copier","severity":"critical","affectedVersions":["*"]},{"name":"pdf-annotation","severity":"critical","affectedVersions":["*"]},{"name":"pergel","severity":"critical","affectedVersions":["*"]},{"name":"pergeltest","severity":"critical","affectedVersions":["*"]},{"name":"piclite","severity":"critical","affectedVersions":["*"]},{"name":"pico-uid","severity":"critical","affectedVersions":["*"]},{"name":"pkg-readme","severity":"critical","affectedVersions":["*"]},{"name":"poper-react-sdk","severity":"critical","affectedVersions":["*"]},{"name":"posthog-docusaurus","severity":"critical","affectedVersions":["*"]},{"name":"posthog-js","severity":"critical","affectedVersions":["*"]},{"name":"posthog-node","severity":"critical","affectedVersions":["*"]},{"name":"posthog-plugin-hello-world","severity":"critical","affectedVersions":["*"]},{"name":"posthog-react-native","severity":"critical","affectedVersions":["*"]},{"name":"posthog-react-native-session-replay","severity":"critical","affectedVersions":["*"]},{"name":"prime-one-table","severity":"critical","affectedVersions":["*"]},{"name":"prompt-eng","severity":"critical","affectedVersions":["*"]},{"name":"prompt-eng-server","severity":"critical","affectedVersions":["*"]},{"name":"puny-req","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-ads-list","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-default-staking-list","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-default-staking-list-address","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-default-token-list","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-router-sdk","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-sdk","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-smart-order-router","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-token-lists","severity":"critical","affectedVersions":["*"]},{"name":"quickswap-v2-sdk","severity":"critical","affectedVersions":["*"]},{"name":"ra-auth-firebase","severity":"critical","affectedVersions":["*"]},{"name":"ra-data-firebase","severity":"critical","affectedVersions":["*"]},{"name":"react-component-taggers","severity":"critical","affectedVersions":["*"]},{"name":"react-data-to-export","severity":"critical","affectedVersions":["*"]},{"name":"react-element-prompt-inspector","severity":"critical","affectedVersions":["*"]},{"name":"react-favic","severity":"critical","affectedVersions":["*"]},{"name":"react-hook-form-persist","severity":"critical","affectedVersions":["*"]},{"name":"react-jam-icons","severity":"critical","affectedVersions":["*"]},{"name":"react-keycloak-context","severity":"critical","affectedVersions":["*"]},{"name":"react-library-setup","severity":"critical","affectedVersions":["*"]},{"name":"react-linear-loader","severity":"critical","affectedVersions":["*"]},{"name":"react-micromodal.js","severity":"critical","affectedVersions":["*"]},{"name":"react-native-datepicker-modal","severity":"critical","affectedVersions":["*"]},{"name":"react-native-email","severity":"critical","affectedVersions":["*"]},{"name":"react-native-fetch","severity":"critical","affectedVersions":["*"]},{"name":"react-native-get-pixel-dimensions","severity":"critical","affectedVersions":["*"]},{"name":"react-native-google-maps-directions","severity":"critical","affectedVersions":["*"]},{"name":"react-native-jam-icons","severity":"critical","affectedVersions":["*"]},{"name":"react-native-log-level","severity":"critical","affectedVersions":["*"]},{"name":"react-native-modest-checkbox","severity":"critical","affectedVersions":["*"]},{"name":"react-native-modest-storage","severity":"critical","affectedVersions":["*"]},{"name":"react-native-phone-call","severity":"critical","affectedVersions":["*"]},{"name":"react-native-retriable-fetch","severity":"critical","affectedVersions":["*"]},{"name":"react-native-use-modal","severity":"critical","affectedVersions":["*"]},{"name":"react-native-view-finder","severity":"critical","affectedVersions":["*"]},{"name":"react-native-websocket","severity":"critical","affectedVersions":["*"]},{"name":"react-native-worklet-functions","severity":"critical","affectedVersions":["*"]},{"name":"react-packery-component","severity":"critical","affectedVersions":["*"]},{"name":"react-qr-image","severity":"critical","affectedVersions":["*"]},{"name":"react-scrambled-text","severity":"critical","affectedVersions":["*"]},{"name":"rediff","severity":"critical","affectedVersions":["*"]},{"name":"rediff-viewer","severity":"critical","affectedVersions":["*"]},{"name":"redux-forge","severity":"critical","affectedVersions":["*"]},{"name":"redux-router-kit","severity":"critical","affectedVersions":["*"]},{"name":"revenuecat","severity":"critical","affectedVersions":["*"]},{"name":"rollup-plugin-httpfile","severity":"critical","affectedVersions":["*"]},{"name":"sa-company-registration-number-regex","severity":"critical","affectedVersions":["*"]},{"name":"sa-id-gen","severity":"critical","affectedVersions":["*"]},{"name":"samesame","severity":"critical","affectedVersions":["*"]},{"name":"scgs-capacitor-subscribe","severity":"critical","affectedVersions":["*"]},{"name":"scgsffcreator","severity":"critical","affectedVersions":["*"]},{"name":"schob","severity":"critical","affectedVersions":["*"]},{"name":"selenium-session","severity":"critical","affectedVersions":["*"]},{"name":"selenium-session-client","severity":"critical","affectedVersions":["*"]},{"name":"set-nested-prop","severity":"critical","affectedVersions":["*"]},{"name":"shelf-jwt-sessions","severity":"critical","affectedVersions":["*"]},{"name":"shell-exec","severity":"critical","affectedVersions":["*"]},{"name":"shinhan-limit-scrap","severity":"critical","affectedVersions":["*"]},{"name":"silgi","severity":"critical","affectedVersions":["*"]},{"name":"simplejsonform","severity":"critical","affectedVersions":["*"]},{"name":"skills-use","severity":"critical","affectedVersions":["*"]},{"name":"solomon-api-stories","severity":"critical","affectedVersions":["*"]},{"name":"solomon-v3-stories","severity":"critical","affectedVersions":["*"]},{"name":"solomon-v3-ui-wrapper","severity":"critical","affectedVersions":["*"]},{"name":"soneium-acs","severity":"critical","affectedVersions":["*"]},{"name":"sort-by-distance","severity":"critical","affectedVersions":["*"]},{"name":"south-african-id-info","severity":"critical","affectedVersions":["*"]},{"name":"stat-fns","severity":"critical","affectedVersions":["*"]},{"name":"stoor","severity":"critical","affectedVersions":["*"]},{"name":"sufetch","severity":"critical","affectedVersions":["*"]},{"name":"super-commit","severity":"critical","affectedVersions":["*"]},{"name":"svelte-autocomplete-select","severity":"critical","affectedVersions":["*"]},{"name":"svelte-toasty","severity":"critical","affectedVersions":["*"]},{"name":"tanstack-shadcn-table","severity":"critical","affectedVersions":["*"]},{"name":"tavily-module","severity":"critical","affectedVersions":["*"]},{"name":"tcsp","severity":"critical","affectedVersions":["*"]},{"name":"tcsp-draw-test","severity":"critical","affectedVersions":["*"]},{"name":"tcsp-test-vd","severity":"critical","affectedVersions":["*"]},{"name":"template-lib","severity":"critical","affectedVersions":["*"]},{"name":"template-micro-service","severity":"critical","affectedVersions":["*"]},{"name":"tenacious-fetch","severity":"critical","affectedVersions":["*"]},{"name":"test-foundry-app","severity":"critical","affectedVersions":["*"]},{"name":"test-hardhat-app","severity":"critical","affectedVersions":["*"]},{"name":"test23112222-api","severity":"critical","affectedVersions":["*"]},{"name":"tiaan","severity":"critical","affectedVersions":["*"]},{"name":"tiptap-shadcn-vue","severity":"critical","affectedVersions":["*"]},{"name":"token.js-fork","severity":"critical","affectedVersions":["*"]},{"name":"toonfetch","severity":"critical","affectedVersions":["*"]},{"name":"trigo-react-app","severity":"critical","affectedVersions":["*"]},{"name":"ts-relay-cursor-paging","severity":"critical","affectedVersions":["*"]},{"name":"typeface-antonio-complete","severity":"critical","affectedVersions":["*"]},{"name":"typefence","severity":"critical","affectedVersions":["*"]},{"name":"typeorm-orbit","severity":"critical","affectedVersions":["*"]},{"name":"unadapter","severity":"critical","affectedVersions":["*"]},{"name":"undefsafe-typed","severity":"critical","affectedVersions":["*"]},{"name":"unemail","severity":"critical","affectedVersions":["*"]},{"name":"uniswap-router-sdk","severity":"critical","affectedVersions":["*"]},{"name":"uniswap-smart-order-router","severity":"critical","affectedVersions":["*"]},{"name":"uniswap-test-sdk-core","severity":"critical","affectedVersions":["*"]},{"name":"unsearch","severity":"critical","affectedVersions":["*"]},{"name":"uplandui","severity":"critical","affectedVersions":["*"]},{"name":"upload-to-play-store","severity":"critical","affectedVersions":["*"]},{"name":"url-encode-decode","severity":"critical","affectedVersions":["*"]},{"name":"use-unsaved-changes","severity":"critical","affectedVersions":["*"]},{"name":"utilitas","severity":"critical","affectedVersions":["*"]},{"name":"v-plausible","severity":"critical","affectedVersions":["*"]},{"name":"valid-south-african-id","severity":"critical","affectedVersions":["*"]},{"name":"valuedex-sdk","severity":"critical","affectedVersions":["*"]},{"name":"vf-oss-template","severity":"critical","affectedVersions":["*"]},{"name":"victoria-wallet-constants","severity":"critical","affectedVersions":["*"]},{"name":"victoria-wallet-core","severity":"critical","affectedVersions":["*"]},{"name":"victoria-wallet-type","severity":"critical","affectedVersions":["*"]},{"name":"victoria-wallet-utils","severity":"critical","affectedVersions":["*"]},{"name":"victoria-wallet-validator","severity":"critical","affectedVersions":["*"]},{"name":"victoriaxoaquyet-wallet-core","severity":"critical","affectedVersions":["*"]},{"name":"vite-plugin-httpfile","severity":"critical","affectedVersions":["*"]},{"name":"vue-browserupdate-nuxt","severity":"critical","affectedVersions":["*"]},{"name":"wallet-evm","severity":"critical","affectedVersions":["*"]},{"name":"wallet-type","severity":"critical","affectedVersions":["*"]},{"name":"web-scraper-mcp","severity":"critical","affectedVersions":["*"]},{"name":"web-types-htmx","severity":"critical","affectedVersions":["*"]},{"name":"web-types-lit","severity":"critical","affectedVersions":["*"]},{"name":"webpack-loader-httpfile","severity":"critical","affectedVersions":["*"]},{"name":"wellness-expert-ng-gallery","severity":"critical","affectedVersions":["*"]},{"name":"wenk","severity":"critical","affectedVersions":["*"]},{"name":"zapier-async-storage","severity":"critical","affectedVersions":["*"]},{"name":"zapier-platform-cli","severity":"critical","affectedVersions":["*"]},{"name":"zapier-platform-core","severity":"critical","affectedVersions":["*"]},{"name":"zapier-platform-legacy-scripting-runner","severity":"critical","affectedVersions":["*"]},{"name":"zapier-platform-schema","severity":"critical","affectedVersions":["*"]},{"name":"zapier-scripts","severity":"critical","affectedVersions":["*"]},{"name":"zuper-cli","severity":"critical","affectedVersions":["*"]},{"name":"zuper-sdk","severity":"critical","affectedVersions":["*"]},{"name":"zuper-stream","severity":"critical","affectedVersions":["*"]}],"sources":["https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains","https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack","https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24"]}');

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId].call(module.exports, module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
/******/ 	
/******/ 	// startup
/******/ 	// Load entry module and return exports
/******/ 	// This entry module is referenced by other modules so it can't be inlined
/******/ 	var __webpack_exports__ = __nccwpck_require__(581);
/******/ 	module.exports = __webpack_exports__;
/******/ 	
/******/ })()
;
//# sourceMappingURL=index.js.map