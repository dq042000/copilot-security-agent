import express from 'express';
import { CopilotClient, approveAll } from '@github/copilot-sdk';
import { Gitlab } from '@gitbeaker/rest';
import * as dotenv from 'dotenv';
import { createHash } from 'node:crypto';

dotenv.config();

const app = express();
app.use(express.json());
const port = Number(process.env.PORT) || 1687;
const model = process.env.COPILOT_MODEL || 'gpt-5-mini';
const defaultScanTimeoutMs = 180000;
const configuredScanTimeoutMs = Number(process.env.COPILOT_SCAN_TIMEOUT_MS);
const scanTimeoutMs = Number.isFinite(configuredScanTimeoutMs) && configuredScanTimeoutMs > 0
  ? configuredScanTimeoutMs
  : defaultScanTimeoutMs;
const defaultScanRetryCount = 1;
const configuredScanRetryCount = Number.parseInt(process.env.COPILOT_SCAN_RETRY_COUNT ?? '', 10);
const scanRetryCount = Number.isInteger(configuredScanRetryCount) && configuredScanRetryCount >= 0
  ? configuredScanRetryCount
  : defaultScanRetryCount;
const defaultScanRetryDelayMs = 1500;
const configuredScanRetryDelayMs = Number(process.env.COPILOT_SCAN_RETRY_DELAY_MS);
const scanRetryDelayMs = Number.isFinite(configuredScanRetryDelayMs) && configuredScanRetryDelayMs >= 0
  ? configuredScanRetryDelayMs
  : defaultScanRetryDelayMs;

// 1. 初始化 Copilot Client (2026 SDK 規範：需維持單一實例以優化效能)
const copilotClient = new CopilotClient();
copilotClient.start()
  .then(() => console.log("Copilot SDK 已啟動"))
  .catch((error) => console.error("Copilot SDK 啟動失敗:", error));

// 2. 初始化 GitLab
const gitlab = new Gitlab({
  host: process.env.GITLAB_URL ?? 'https://gitlab.com',
  token: process.env.GITLAB_TOKEN!,
});

/**
 * 輔助函數：從 Git Remote URL 解析 Project Path
 * 支援: https://gitlab.com/group/project.git 或 git@gitlab.com:group/project.git
 */
function parseProjectPath(remoteUrl: string): string {
  try {
    return remoteUrl
      .replace(/^(https:\/\/|git@).*?[:/]/, '') // 去除前綴
      .replace(/\.git$/, '');                  // 去除 .git 結尾
  } catch {
    return "";
  }
}

interface ScanFinding {
  line?: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  severity?: string;
  title?: string;
  description?: string;
  suggestion?: string;
}

interface ScanRequest {
  code: string;
  fileName: string;
  remoteUrl?: string;
  user?: string;
}

interface ScanResponse {
  findings: ScanFinding[];
  issueId?: number;
}

const inFlightScans = new Map<string, Promise<ScanResponse>>();
type CanonicalSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const severityCanonicalMap: Record<string, CanonicalSeverity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  嚴重: 'critical',
  高: 'high',
  中: 'medium',
  低: 'low',
  資訊: 'info',
};

const severityTraditionalMap: Record<CanonicalSeverity, string> = {
  critical: '嚴重',
  high: '高',
  medium: '中',
  low: '低',
  info: '資訊',
};

/**
 * 解析 AI 回應中的 JSON findings 陣列。
 * AI 被要求回傳 ```json ... ``` 包裹的 JSON，此函數負責提取並驗證。
 */
function parseFindings(content: string): ScanFinding[] {
  const jsonMatch = content.match(/```json\s*([\s\S]*?)```/);
  if (!jsonMatch) return [];

  try {
    const parsed = JSON.parse(jsonMatch[1]!);
    const arr = Array.isArray(parsed) ? parsed : parsed?.findings;
    if (!Array.isArray(arr)) return [];

    return arr.map((f: Record<string, unknown>): ScanFinding => {
      const finding: ScanFinding = {};
      if (typeof f.line === 'number') finding.line = f.line;
      if (typeof f.column === 'number') finding.column = f.column;
      if (typeof f.endLine === 'number') finding.endLine = f.endLine;
      if (typeof f.endColumn === 'number') finding.endColumn = f.endColumn;
      const rawSeverity = typeof f.severity === 'string'
        ? f.severity
        : typeof f.type === 'string'
          ? f.type
          : undefined;
      const traditionalSeverity = toTraditionalSeverity(rawSeverity);
      if (traditionalSeverity) finding.severity = traditionalSeverity;
      if (typeof f.title === 'string') finding.title = f.title;
      if (typeof f.description === 'string') finding.description = f.description;
      if (typeof f.suggestion === 'string') finding.suggestion = f.suggestion;
      return finding;
    });
  } catch {
    return [];
  }
}

function normalizeSeverity(severity?: string): CanonicalSeverity | undefined {
  if (!severity) {
    return undefined;
  }

  const trimmed = severity.trim();
  if (!trimmed) {
    return undefined;
  }

  return severityCanonicalMap[trimmed.toLowerCase()] ?? severityCanonicalMap[trimmed];
}

function toTraditionalSeverity(severity?: string): string | undefined {
  const normalized = normalizeSeverity(severity);
  if (normalized) {
    return severityTraditionalMap[normalized];
  }

  const trimmed = severity?.trim();
  return trimmed ? trimmed : undefined;
}

function buildScanKey({ code, fileName, remoteUrl, user }: ScanRequest): string {
  return createHash('sha256')
    .update(`${user ?? 'unknown'}\n${fileName}\n${remoteUrl ?? ''}\n${code}`)
    .digest('hex');
}

function isSessionIdleTimeoutError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  return error.message.includes('Timeout after') && error.message.includes('session.idle');
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildCodeContextSnippet(
  sourceCode: string,
  line: number,
  radius = 2,
): { startLine: number; endLine: number; snippet: string } | undefined {
  if (!Number.isInteger(line) || line < 1) {
    return undefined;
  }

  const lines = sourceCode.split(/\r?\n/);
  if (lines.length === 0) {
    return undefined;
  }

  const targetLine = Math.min(line, lines.length);
  const startLine = Math.max(1, targetLine - radius);
  const endLine = Math.min(lines.length, targetLine + radius);
  const snippet = lines
    .slice(startLine - 1, endLine)
    .map((content, index) => `${startLine + index} | ${content}`)
    .join('\n');

  return {
    startLine,
    endLine,
    snippet,
  };
}

function getSeveritySortOrder(severity?: string): number {
  switch (normalizeSeverity(severity)) {
    case 'critical':
      return 0;
    case 'high':
      return 1;
    case 'medium':
      return 2;
    case 'low':
      return 3;
    case 'info':
      return 4;
    default:
      return 5;
  }
}

async function runCopilotScanWithRetry(systemPrompt: string, fileName: string, user?: string): Promise<string> {
  const maxAttempts = scanRetryCount + 1;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    let session: Awaited<ReturnType<typeof copilotClient.createSession>> | undefined;
    try {
      session = await copilotClient.createSession({
        model,
        onPermissionRequest: approveAll,
      });

      const response = await session.sendAndWait(
        { prompt: `${systemPrompt}\n\n請分析此檔案的安全性。` },
        scanTimeoutMs,
      );

      return response?.data?.content ?? "";
    } catch (error) {
      const shouldRetry = attempt < maxAttempts && isSessionIdleTimeoutError(error);
      const message = error instanceof Error ? error.message : String(error);
      console.warn(
        `[scan] file=${fileName}, user=${user ?? 'unknown'}, attempt=${attempt}/${maxAttempts}, error=${message}${shouldRetry ? ', retrying' : ''}`,
      );

      if (!shouldRetry) {
        throw error;
      }

      if (scanRetryDelayMs > 0) {
        await wait(scanRetryDelayMs);
      }
    } finally {
      if (session) {
        await session.destroy();
      }
    }
  }

  throw new Error('Scan failed unexpectedly after retries');
}

async function scanFile({ code, fileName, remoteUrl, user }: ScanRequest): Promise<ScanResponse> {
  const systemPrompt = `你是一位資安專家。請分析以下程式碼檔案的安全性。

檔案名稱：${fileName}

程式碼：
${code}

要求：
1. 識別 OWASP Top 10 漏洞（包含 Injection、Broken Access Control、Cryptographic Failures、XSS 等）。
2. 對每個發現的漏洞，提供精確的行號位置、嚴重等級、說明與修復建議。
3. 嚴重等級請用繁體中文：嚴重、高、中、低、資訊（由高到低）。

你 **必須** 用以下 JSON 格式回傳所有發現，用 \`\`\`json ... \`\`\` 包裹：

\`\`\`json
[
  {
    "line": 10,
    "endLine": 10,
    "column": 1,
    "endColumn": 50,
    "severity": "高",
    "title": "SQL Injection",
    "description": "直接拼接使用者輸入至 SQL 查詢，可能導致 SQL 注入攻擊。",
    "suggestion": "使用參數化查詢或 ORM 來避免 SQL 注入。"
  }
]
\`\`\`

如果沒有發現任何漏洞，回傳空陣列：\`\`\`json\n[]\n\`\`\``;

  const resultContent = await runCopilotScanWithRetry(systemPrompt, fileName, user);
  const findings = parseFindings(resultContent);

  console.log(`[scan] file=${fileName}, findings=${findings.length}`);

  let issueId: number | undefined;
  const hasCritical = findings.some((f) => {
    const normalized = normalizeSeverity(f.severity);
    return normalized === 'critical' || normalized === 'high';
  });

  if (hasCritical && remoteUrl) {
    const projectPath = parseProjectPath(remoteUrl);

    if (projectPath) {
      const sortedFindings = [...findings].sort((a, b) => {
        const severityOrderDiff = getSeveritySortOrder(a.severity) - getSeveritySortOrder(b.severity);
        if (severityOrderDiff !== 0) {
          return severityOrderDiff;
        }

        const lineA = typeof a.line === 'number' ? a.line : Number.MAX_SAFE_INTEGER;
        const lineB = typeof b.line === 'number' ? b.line : Number.MAX_SAFE_INTEGER;
        return lineA - lineB;
      });

      const issueDescription = sortedFindings
        .map((f) => {
          const codeContext = typeof f.line === 'number'
            ? buildCodeContextSnippet(code, f.line, 2)
            : undefined;
          const codeContextSection = codeContext
            ? `- **程式碼片段（第 ${codeContext.startLine} ~ ${codeContext.endLine} 行）**:\n\`\`\`\n${codeContext.snippet}\n\`\`\`\n`
            : '';
          const severityLabel = toTraditionalSeverity(f.severity) ?? '未知';

          return `### ${severityLabel}: ${f.title ?? '未命名'}\n` +
            `- **位置**: 第 ${f.line ?? '?'} 行\n` +
            `- **說明**: ${f.description ?? '無'}\n` +
            `- **建議**: ${f.suggestion ?? '無'}\n` +
            codeContextSection;
        })
        .join('\n');

      const issue = await gitlab.Issues.create(projectPath, `🛡️ AI 弱掃預警: ${fileName}`, {
        description: `## 漏洞分析報告\n\n${issueDescription}\n\n---\n*來源: 內部 AI 安全助理*`,
        labels: 'security,ai-detected',
      });
      issueId = (issue as { iid?: number }).iid;
      console.log(`[scan] GitLab Issue #${issueId} created for ${projectPath}`);
    }
  }

  return {
    findings,
    ...(issueId !== undefined && { issueId }),
  };
}

app.post('/scan', async (req, res) => {
  try {
    const { code, fileName, remoteUrl, user } = req.body as Partial<ScanRequest>;

    // 基本請求驗證
    if (!code || typeof code !== 'string' || !code.trim()) {
      res.status(400).json({ error: '缺少必要欄位: code' });
      return;
    }
    if (!fileName || typeof fileName !== 'string') {
      res.status(400).json({ error: '缺少必要欄位: fileName' });
      return;
    }

    const scanRequest: ScanRequest = {
      code,
      fileName,
      ...(typeof remoteUrl === 'string' ? { remoteUrl } : {}),
      ...(typeof user === 'string' ? { user } : {}),
    };
    const scanKey = buildScanKey(scanRequest);
    const existingScan = inFlightScans.get(scanKey);

    if (existingScan) {
      console.log(`[scan] dedupe-hit file=${fileName}, user=${scanRequest.user ?? 'unknown'}`);
      const dedupedResult = await existingScan;
      res.json(dedupedResult);
      return;
    }

    console.log(
      `[scan] file=${fileName}, user=${scanRequest.user ?? 'unknown'}, code_length=${code.length}, timeout_ms=${scanTimeoutMs}, max_attempts=${scanRetryCount + 1}`,
    );

    const scanPromise = scanFile(scanRequest).finally(() => {
      inFlightScans.delete(scanKey);
    });
    inFlightScans.set(scanKey, scanPromise);

    const scanResponse = await scanPromise;
    res.json(scanResponse);
  } catch (error: unknown) {
    console.error("Scan Error:", error);
    const message = error instanceof Error ? error.message : "Internal Server Error";
    res.status(500).json({ error: message });
  }
});

// 優雅關閉
process.on('SIGINT', async () => {
  await copilotClient.stop();
  process.exit(0);
});

app.listen(port, () => console.log(`🛡️ Security Agent 正在 port ${port} 運行...`));
