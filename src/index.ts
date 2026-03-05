import express from 'express';
import { CopilotRuntime, CopilotChain } from '@github/copilot-sdk';
import { GitLab } from '@gitbeaker/rest';
import * as dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());

// 初始化 GitLab API
const gitlab = new GitLab({
  host: process.env.GITLAB_URL,
  token: process.env.GITLAB_TOKEN,
});

app.post('/agent', async (req, res) => {
  try {
    // 1. 從請求中提取上下文 (Context)
    // payload 包含：messages (對話紀錄), context (目前開啟的檔案內容)
    const { messages, context } = req.json();
    const currentCode = context.active_file?.content || "無檔案內容";
    const fileName = context.active_file?.name || "未知檔案";

    // 2. 建立安全專家 Prompt
    const systemPrompt = `你是一位資安專家。請分析以下程式碼：\n${currentCode}\n
    如果發現 OWASP 漏洞，請詳細列出。並請用 JSON 格式回傳一個摘要給後台紀錄。`;

    // 3. 呼叫 Copilot SDK 進行推理 (串流模式)
    const runtime = new CopilotRuntime();
    const result = await runtime.stream(messages, {
      systemPrompt,
      // 這裡可以定義自定義 Skills，例如 "createGitLabIssue"
    });

    // 4. (非同步) 如果發現嚴重問題，回寫 GitLab Issue
    // 注意：這裡通常會先解析 AI 的回答，若有 [CRITICAL] 標籤才觸發
    if (result.content.includes("CRITICAL")) {
        await gitlab.Issues.create('PROJECT_ID', {
            title: `[Security Alert] ${fileName} 發現潛在漏洞`,
            description: `AI 掃描結果摘要：\n${result.content}`,
            labels: ['security-bot', 'automated-scan']
        });
    }

    // 5. 將結果回傳給 VS Code Chat
    return result.pipe(res);

  } catch (error) {
    console.error("Agent Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.listen(3000, () => console.log('Security Agent 正在 port 3000 運行...'));
