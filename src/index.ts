import express from 'express';
import { CopilotClient, approveAll } from '@github/copilot-sdk';
import { Gitlab } from '@gitbeaker/rest';
import * as dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());

const copilotClient = new CopilotClient();
const gitlabToken = process.env.GITLAB_TOKEN;
const gitlabHost = process.env.GITLAB_URL ?? 'https://gitlab.com';

if (!gitlabToken) {
  throw new Error('GITLAB_TOKEN is required');
}

// 初始化 GitLab API
const gitlab = new Gitlab({
  host: gitlabHost,
  token: gitlabToken,
});

app.post('/agent', async (req, res) => {
  try {
    // 1. 從請求中提取上下文 (Context)
    // payload 包含：messages (對話紀錄), context (目前開啟的檔案內容)
    const { messages, context } = req.body;
    const currentCode = context.active_file?.content || "無檔案內容";
    const fileName = context.active_file?.name || "未知檔案";

    // 2. 建立安全專家 Prompt
    const systemPrompt = `你是一位資安專家。請分析以下程式碼：\n${currentCode}\n
    如果發現 OWASP 漏洞，請詳細列出。並請用 JSON 格式回傳一個摘要給後台紀錄。`;

    // 3. 呼叫 Copilot SDK 進行推理
    const session = await copilotClient.createSession({
      model: 'gpt-5',
      onPermissionRequest: approveAll,
      systemMessage: {
        mode: 'append',
        content: systemPrompt,
      },
    });
    const prompt = Array.isArray(messages)
      ? messages
          .map((message) => {
            if (typeof message === 'string') return message;
            if (message?.content) return String(message.content);
            return '';
          })
          .filter(Boolean)
          .join('\n')
      : '請分析目前檔案中的潛在安全問題。';

    const response = await session.sendAndWait({ prompt });
    const resultContent = response?.data?.content ?? '';

    // 4. (非同步) 如果發現嚴重問題，回寫 GitLab Issue
    // 注意：這裡通常會先解析 AI 的回答，若有 [CRITICAL] 標籤才觸發
    if (resultContent.includes('CRITICAL')) {
      const projectId = process.env.GITLAB_PROJECT_ID ?? 'PROJECT_ID';
      await gitlab.Issues.create(
        projectId,
        `[Security Alert] ${fileName} 發現潛在漏洞`,
        {
          description: `AI 掃描結果摘要：\n${resultContent}`,
          labels: 'security-bot,automated-scan',
        }
      );
    }

    await session.destroy();

    // 5. 將結果回傳給 VS Code Chat
    return res.json({
      content: resultContent,
    });

  } catch (error) {
    console.error("Agent Error:", error);
    res.status(500).send("Internal Server Error");
  }
});

app.listen(3000, () => console.log('Security Agent 正在 port 3000 運行...'));
