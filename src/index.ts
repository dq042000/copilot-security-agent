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

app.post('/scan', async (req, res) => {
  let session;
  try {
    const { code, fileName, remoteUrl, messages } = req.body;

    // 2. 建立 AI 掃描會話
    session = await copilotClient.createSession({
      model,
      onPermissionRequest: approveAll,
    });

    const systemPrompt = `你是一位資安專家。請分析以下程式碼檔案 ${fileName}：\n\n${code}\n\n
    要求：
    1. 識別 OWASP Top 10 漏洞。
    2. 如果發現漏洞，請在回應開頭標註 [CRITICAL] 標籤。
    3. 提供修復建議代碼。`;

    // 3. 執行分析
    const userPrompt = messages?.[0]?.content || "請分析此檔案的安全性。";
    const response = await session.sendAndWait({
      prompt: `${systemPrompt}\n\n用戶提問：${userPrompt}`
    });

    const resultContent = response?.data?.content ?? "AI 未回傳結果";

    // 4. 自動回寫 GitLab Issue
    if (resultContent.includes('[CRITICAL]')) {
      const projectPath = parseProjectPath(remoteUrl);
      
      if (projectPath) {
        await gitlab.Issues.create(projectPath, `🛡️ AI 弱掃預警: ${fileName}`, {
          description: `## 漏洞分析報告\n\n${resultContent}\n\n---\n*來源: 內部 AI 安全助理*`,
          labels: 'security,ai-detected',
        });
        console.log(`已在 GitLab 專案 ${projectPath} 建立 Issue`);
      }
    }

    // 5. 回傳給 VS Code
    res.json({
      content: resultContent,
      status: 'success'
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