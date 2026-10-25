import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';

import type {
  GetIssueVulnerabilityDataRequest,
  GetScanFindingsRequest,
  RetryIssueCreationRequest,
  SaveScanConfigRequest,
  ScanConfiguration,
  ScanHistoryEntry,
  VulnerabilityFinding,
} from '../types/app';
import { FINDING_PROPERTY_KEY } from '../types/app';
import { normalizeScanProfile, validateHttpUrl, isSeverity } from './validation';
import { resolveProvider, supportedHostsMessage } from './providers';
import { ExternalScannerAdapter, ScannerError } from './scanner-adapter';
import {
  ScanOrchestrationService,
  NotConfiguredError,
  RateLimitedError,
} from './orchestration-service';
import {
  listScans,
  readApiKey,
  readConfig,
  readFindings,
  readScan,
  writeApiKey,
  writeConfig,
} from './storage-service';

interface ResolverRequest<P> {
  payload?: P;
  context?: {
    accountId?: string;
    cloudId?: string;
    extension?: {
      issue?: { key?: string; id?: string };
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
}

const orchestration = new ScanOrchestrationService();
const resolver = new Resolver();

// -----------------------------------------------------------------------------
// logError — receives structured frontend error reports for Forge logging.
// Used by the frontend global error handlers and ErrorBoundary.
// -----------------------------------------------------------------------------

interface FrontendErrorReport {
  message: string;
  stack?: string;
  source?: string;
  lineno?: number;
  colno?: number;
  timestamp?: string;
  userAgent?: string;
  url?: string;
  errorType?: string;
  componentStack?: string;
}

resolver.define('logError', (req: ResolverRequest<FrontendErrorReport>): { success: boolean } => {
  const data = req.payload;
  console.error('[Frontend Error]', {
    message: data?.message,
    stack: data?.stack,
    source: data?.source,
    line: data?.lineno,
    column: data?.colno,
    timestamp: data?.timestamp,
    errorType: data?.errorType,
    componentStack: data?.componentStack,
  });
  return { success: true };
});

// -----------------------------------------------------------------------------
// getScanConfig
// -----------------------------------------------------------------------------

resolver.define('getScanConfig', async (): Promise<ScanConfiguration> => {
  try {
    const config = await readConfig();
    const hasApiKey = (await readApiKey()) !== null;
    if (!config) {
      return { apiBaseUrl: '', hasApiKey: false, updatedAt: '', provider: '' };
    }
    const provider = resolveProvider(config.apiBaseUrl);
    return {
      apiBaseUrl: config.apiBaseUrl,
      hasApiKey,
      updatedAt: config.updatedAt,
      provider: provider?.id ?? '',
    };
  } catch (error) {
    console.error('getScanConfig failed:', error);
    return { apiBaseUrl: '', hasApiKey: false, updatedAt: '', provider: '' };
  }
});

// -----------------------------------------------------------------------------
// saveScanConfig
// -----------------------------------------------------------------------------

resolver.define(
  'saveScanConfig',
  async (req: ResolverRequest<SaveScanConfigRequest>): Promise<ScanConfiguration> => {
    const payload = req.payload;
    const apiBaseUrl = payload?.apiBaseUrl ?? '';
    const apiKey = payload?.apiKey ?? '';

    const urlCheck = validateHttpUrl(apiBaseUrl);
    if (!urlCheck.valid) {
      throw new Error(`Invalid API base URL: ${urlCheck.reason}`);
    }
    if (typeof apiKey !== 'string' || apiKey.trim() === '') {
      throw new Error('An API key is required.');
    }

    const provider = resolveProvider(apiBaseUrl);
    if (!provider) {
      throw new Error(
        `The host is not a supported scanning provider. Supported providers: ${supportedHostsMessage()}.`,
      );
    }

    // Validate the connection with a lightweight test call before saving.
    const adapter = new ExternalScannerAdapter(apiBaseUrl.trim(), apiKey);
    try {
      await adapter.testConnection(provider.paths.test);
    } catch (error) {
      if (error instanceof ScannerError) {
        // Never leak the key; surface a connection-oriented message only.
        throw new Error(
          error.kind === 'connection'
            ? 'Could not connect to the scanning service. Check the base URL and try again.'
            : `The scanning service rejected the connection test (HTTP ${error.status ?? '?'}). Check your API key.`,
        );
      }
      throw new Error('Failed to validate the scanning service connection.');
    }

    const updatedAt = new Date().toISOString();
    await writeConfig(apiBaseUrl.trim(), updatedAt);
    await writeApiKey(apiKey);

    return {
      apiBaseUrl: apiBaseUrl.trim(),
      hasApiKey: true,
      updatedAt,
      provider: provider.id,
    };
  },
);

// -----------------------------------------------------------------------------
// triggerScan
// -----------------------------------------------------------------------------

resolver.define(
  'triggerScan',
  async (
    req: ResolverRequest<{ targetUrl: string; scanProfile: string }>,
  ): Promise<ScanHistoryEntry> => {
    const accountId = req.context?.accountId ?? 'anonymous';
    const targetUrl = req.payload?.targetUrl ?? '';
    const profile = normalizeScanProfile(req.payload?.scanProfile);

    const urlCheck = validateHttpUrl(targetUrl);
    if (!urlCheck.valid) {
      throw new Error(`Invalid target URL: ${urlCheck.reason}`);
    }

    try {
      return await orchestration.triggerScan(accountId, targetUrl.trim(), profile);
    } catch (error) {
      if (error instanceof NotConfiguredError || error instanceof RateLimitedError) {
        throw new Error(error.message);
      }
      if (error instanceof ScannerError) {
        throw new Error(
          `Failed to start scan (HTTP ${error.status ?? 'network error'}): ${error.message}`,
        );
      }
      console.error('triggerScan failed:', error);
      throw new Error('Failed to start the scan. Please try again.');
    }
  },
);

// -----------------------------------------------------------------------------
// getScanHistory
// -----------------------------------------------------------------------------

resolver.define('getScanHistory', async (): Promise<ScanHistoryEntry[]> => {
  try {
    return await listScans(50);
  } catch (error) {
    console.error('getScanHistory failed:', error);
    return [];
  }
});

// -----------------------------------------------------------------------------
// getScanFindings
// -----------------------------------------------------------------------------

resolver.define(
  'getScanFindings',
  async (req: ResolverRequest<GetScanFindingsRequest>): Promise<VulnerabilityFinding[]> => {
    const scanId = req.payload?.scanId ?? '';
    if (!scanId) {
      throw new Error('A scanId is required.');
    }
    const entry = await readScan(scanId);
    if (!entry) {
      const err = new Error(`Scan ${scanId} was not found.`) as Error & { code?: string };
      err.code = 'not_found';
      throw err;
    }

    let findings = await readFindings(scanId);
    const severityFilter = req.payload?.severity;
    const categoryFilter = req.payload?.owaspCategory;
    if (severityFilter && isSeverity(severityFilter)) {
      findings = findings.filter((f) => f.severity === severityFilter);
    }
    if (categoryFilter) {
      findings = findings.filter((f) => f.owaspCategory === categoryFilter);
    }
    return findings;
  },
);

// -----------------------------------------------------------------------------
// getIssueVulnerabilityData
// -----------------------------------------------------------------------------

resolver.define(
  'getIssueVulnerabilityData',
  async (
    req: ResolverRequest<GetIssueVulnerabilityDataRequest>,
  ): Promise<VulnerabilityFinding | null> => {
    const issueKey = req.payload?.issueKey ?? req.context?.extension?.issue?.key;
    if (!issueKey) {
      return null;
    }
    try {
      const response = await api
        .asApp()
        .requestJira(
          route`/rest/api/3/issue/${issueKey}/properties/${FINDING_PROPERTY_KEY}`,
        );
      if (response.status === 404) {
        return null;
      }
      if (!response.ok) {
        console.error(
          `getIssueVulnerabilityData: Jira returned ${response.status} for ${issueKey}`,
        );
        return null;
      }
      const body = (await response.json()) as { value?: VulnerabilityFinding };
      return body.value ?? null;
    } catch (error) {
      console.error('getIssueVulnerabilityData failed:', error);
      return null;
    }
  },
);

// -----------------------------------------------------------------------------
// retryIssueCreation — reprocess findings for a scan with partial failures
// -----------------------------------------------------------------------------

resolver.define(
  'retryIssueCreation',
  async (req: ResolverRequest<RetryIssueCreationRequest>): Promise<ScanHistoryEntry> => {
    const scanId = req.payload?.scanId ?? '';
    if (!scanId) {
      throw new Error('A scanId is required.');
    }
    const entry = await readScan(scanId);
    if (!entry) {
      throw new Error(`Scan ${scanId} was not found.`);
    }
    try {
      // Force reprocessing by clearing the processed flag path via processScanResults,
      // which merges existing findings and only creates issues for uncreated ones.
      const result = await orchestration.processScanResults(scanId);
      return result ?? entry;
    } catch (error) {
      if (error instanceof NotConfiguredError) {
        throw new Error(error.message);
      }
      console.error('retryIssueCreation failed:', error);
      throw new Error('Failed to retry issue creation for this scan.');
    }
  },
);

export const handler = resolver.getDefinitions();

// The web trigger (`scanWebhook`) and scheduled trigger (`scanPoller`) handlers
// live in `src/index.ts` — the file referenced by the manifest — so their
// request-authentication guard is visible where the platform loads them.
export { orchestration };
