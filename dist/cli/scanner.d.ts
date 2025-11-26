import { PackageJson, PackageLock, ScanResult, ScanSummary, SarifResult, SecurityFinding } from './types';
export declare function isAffected(packageName: string): boolean;
export declare function getPackageSeverity(packageName: string): 'critical' | 'high' | 'medium' | 'low';
export declare function parsePackageJson(filePath: string): PackageJson | null;
export declare function parsePackageLock(filePath: string): PackageLock | null;
export declare function parseYarnLock(filePath: string): Map<string, string> | null;
export declare function scanPackageJson(filePath: string, isDirect?: boolean): ScanResult[];
export declare function scanPackageLock(filePath: string): ScanResult[];
export declare function scanYarnLock(filePath: string): ScanResult[];
export declare function findLockfiles(directory: string): string[];
export declare function findPackageJsonFiles(directory: string): string[];
/**
 * Check package.json scripts for suspicious patterns
 */
export declare function checkSuspiciousScripts(filePath: string): SecurityFinding[];
/**
 * Check for TruffleHog activity and credential scanning patterns
 */
export declare function checkTrufflehogActivity(directory: string): SecurityFinding[];
/**
 * Check for actionsSecrets.json exfiltration files
 */
export declare function checkSecretsExfiltration(directory: string): SecurityFinding[];
/**
 * Check GitHub Actions workflows for malicious runners
 */
export declare function checkMaliciousRunners(directory: string): SecurityFinding[];
/**
 * Check for Shai-Hulud git repository references
 */
export declare function checkShaiHuludRepos(directory: string): SecurityFinding[];
/**
 * Check for packages from affected namespaces (low-risk warning)
 */
export declare function checkAffectedNamespaces(filePath: string): SecurityFinding[];
/**
 * Check for suspicious git branches
 */
export declare function checkSuspiciousBranches(directory: string): SecurityFinding[];
export declare function runScan(directory: string, scanLockfiles?: boolean): ScanSummary;
export declare function generateSarifReport(summary: ScanSummary): SarifResult;
export declare function formatTextReport(summary: ScanSummary): string;
export declare function getMasterPackagesInfo(): {
    version: string;
    lastUpdated: string;
    totalPackages: number;
    attackInfo: {
        name: string;
        alias: string;
        firstDetected: string;
        description: string;
    };
    indicators: {
        maliciousFiles: string[];
        maliciousWorkflows: string[];
        fileHashes: Record<string, string>;
        gitHubIndicators: {
            runnerName: string;
            repoDescription: string;
        };
    };
};
