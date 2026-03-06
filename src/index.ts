import express from 'express';
import { CopilotClient, approveAll } from '@github/copilot-sdk';
import { Gitlab } from '@gitbeaker/rest';
import * as dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());
const port = Number(process.env.PORT) || 1687;
const model = process.env.COPILOT_MODEL || 'gpt-5-mini';

// 1. 初始化 Copilot Client (2026 SDK 規範：需維持單一實例以優化效能)
const copilotClient = new CopilotClient();
copilotClient.start().then(() => console.log("Copilot SDK 已啟動"));

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
      if (typeof f.severity === 'string') finding.severity = f.severity;
      if (typeof f.title === 'string') finding.title = f.title;
      if (typeof f.description === 'string') finding.description = f.description;
      if (typeof f.suggestion === 'string') finding.suggestion = f.suggestion;
      return finding;
    });
  } catch {
    return [];
  }
}

app.post('/scan', async (req, res) => {
  let session;
  try {
    const { code, fileName, remoteUrl, user } = req.body;

    // 基本請求驗證
    if (!code || typeof code !== 'string' || !code.trim()) {
      res.status(400).json({ error: '缺少必要欄位: code' });
      return;
    }
    if (!fileName || typeof fileName !== 'string') {
      res.status(400).json({ error: '缺少必要欄位: fileName' });
      return;
    }

    console.log(`[scan] file=${fileName}, user=${user ?? 'unknown'}, code_length=${code.length}`);

    // 建立 AI 掃描會話
    session = await copilotClient.createSession({
      model,
      onPermissionRequest: approveAll,
    });

    const systemPrompt = `你是一位資安專家。請分析以下程式碼檔案的安全性。

檔案名稱：${fileName}

程式碼：
${code}

要求：
1. 識別 OWASP Top 10 漏洞（包含 Injection、Broken Access Control、Cryptographic Failures、XSS 等）。
2. 對每個發現的漏洞，提供精確的行號位置、嚴重等級、說明與修復建議。
3. 嚴重等級請用：critical、high、medium、low、info。

你 **必須** 用以下 JSON 格式回傳所有發現，用 \`\`\`json ... \`\`\` 包裹：

\`\`\`json
[
  {
    "line": 10,
    "endLine": 10,
    "column": 1,
    "endColumn": 50,
    "severity": "high",
    "title": "SQL Injection",
    "description": "直接拼接使用者輸入至 SQL 查詢，可能導致 SQL 注入攻擊。",
    "suggestion": "使用參數化查詢或 ORM 來避免 SQL 注入。"
  }
]
\`\`\`

如果沒有發現任何漏洞，回傳空陣列：\`\`\`json\n[]\n\`\`\``;

    // 執行分析
    const response = await session.sendAndWait({
      prompt: `${systemPrompt}\n\n請分析此檔案的安全性。`
    });

    const resultContent = response?.data?.content ?? "";
    const findings = parseFindings(resultContent);

    console.log(`[scan] file=${fileName}, findings=${findings.length}`);

    // 判斷是否有 critical/high 等級的弱點需建立 GitLab Issue
    let issueId: number | undefined;
    const hasCritical = findings.some(
      f => f.severity === 'critical' || f.severity === 'high'
    );

    if (hasCritical && remoteUrl) {
      const projectPath = parseProjectPath(remoteUrl);

      if (projectPath) {
        const issueDescription = findings
          .map(f => `### ${f.severity?.toUpperCase()}: ${f.title ?? '未命名'}\n` +
            `- **位置**: 第 ${f.line ?? '?'} 行\n` +
            `- **說明**: ${f.description ?? '無'}\n` +
            `- **建議**: ${f.suggestion ?? '無'}\n`)
          .join('\n');

        const issue = await gitlab.Issues.create(projectPath, `🛡️ AI 弱掃預警: ${fileName}`, {
          description: `## 漏洞分析報告\n\n${issueDescription}\n\n---\n*來源: 內部 AI 安全助理*`,
          labels: 'security,ai-detected',
        });
        issueId = (issue as { iid?: number }).iid;
        console.log(`[scan] GitLab Issue #${issueId} created for ${projectPath}`);
      }
    }

    // 回傳符合 Scanner ScanResponse 介面的結構
    res.json({
      findings,
      ...(issueId !== undefined && { issueId }),
    });

  } catch (error: any) {
    console.error("Scan Error:", error);
    res.status(500).json({ error: error.message || "Internal Server Error" });
  } finally {
    if (session) await session.destroy();
  }
});

// 優雅關閉
process.on('SIGINT', async () => {
  await copilotClient.stop();
  process.exit(0);
});

app.listen(port, () => console.log(`🛡️ Security Agent 正在 port ${port} 運行...`));