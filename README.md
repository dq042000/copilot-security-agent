# Copilot Security Agent

Copilot Security Agent 是一個以 Node.js/TypeScript 實作的安全掃描服務，提供 `POST /scan` API，使用 GitHub Copilot SDK 分析程式碼弱點，並可在高風險情境下自動建立 GitLab Issue。

## 主要功能

- 透過 API 接收程式碼並進行弱點分析（聚焦 OWASP Top 10 類型風險）。
- 解析並回傳結構化掃描結果（行號、嚴重等級、描述、修補建議）。
- 嚴重等級統一使用繁體中文顯示：`嚴重 > 高 > 中 > 低 > 資訊`。
- 對 Copilot 掃描提供逾時重試機制（`session.idle` timeout）。
- 以請求內容雜湊避免重複掃描（in-flight dedupe）。
- 當發現高風險（嚴重/高）且提供 Git 專案 remote URL 時，自動建立 GitLab Issue。

## 專案需求

- 可執行 `npm` 的 Node.js 環境
- GitLab Personal Access Token（用於建立 Issue）

## 安裝與設定

```bash
npm install
cp env-sample .env
```

編輯 `.env`（可參考 `env-sample`）：

| 變數 | 預設值 | 說明 |
| --- | --- | --- |
| `GITLAB_URL` | `https://gitlab.com` | GitLab 服務位址 |
| `GITLAB_TOKEN` | （無） | **必要**，用於建立 GitLab Issue |
| `PORT` | `1687` | 服務埠號 |
| `COPILOT_MODEL` | `gpt-5-mini` | 掃描使用的 Copilot 模型 |
| `COPILOT_SCAN_TIMEOUT_MS` | `180000` | 單次掃描逾時毫秒數 |
| `COPILOT_SCAN_RETRY_COUNT` | `1` | 逾時後重試次數 |
| `COPILOT_SCAN_RETRY_DELAY_MS` | `1500` | 重試間隔毫秒數 |

## 啟動方式

```bash
# 直接啟動
npm run start

# 開發模式（檔案變更自動重啟）
npm run dev

# TypeScript 編譯
npm run build
```

### PM2（選用）

> `start:bg` 會執行 `dist/index.js`，請先 `npm run build`。

```bash
npm run start:bg
npm run start:logs
npm run start:restart
npm run start:stop
npm run start:remove
```

## API 說明

### `POST /scan`

請求 Body：

| 欄位 | 型別 | 必填 | 說明 |
| --- | --- | --- | --- |
| `code` | `string` | 是 | 要掃描的原始碼（不可為空字串） |
| `fileName` | `string` | 是 | 檔案名稱（例：`app.js`） |
| `remoteUrl` | `string` | 否 | Git remote URL（用於推導 GitLab project path） |
| `user` | `string` | 否 | 呼叫者識別資訊（用於記錄） |

範例：

```bash
curl -X POST http://localhost:1687/scan \
  -H "Content-Type: application/json" \
  -d '{
    "fileName": "app.js",
    "code": "const sql = \"SELECT * FROM users WHERE id = \" + req.query.id;",
    "remoteUrl": "https://gitlab.com/group/project.git",
    "user": "alice"
  }'
```

成功回應（`200`）：

```json
{
  "findings": [
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
  ],
  "issueId": 123
}
```

> `issueId` 僅在符合建立 Issue 條件時出現（有高風險 findings 且可解析 `remoteUrl`）。

錯誤回應：

- `400`：缺少必要欄位（如 `code` 或 `fileName`）
- `500`：掃描流程失敗或外部服務錯誤

## 嚴重等級對照

系統會將嚴重等級標準化並以繁中輸出：

- `critical` / `嚴重` → `嚴重`
- `high` / `高` → `高`
- `medium` / `中` → `中`
- `low` / `低` → `低`
- `info` / `資訊` → `資訊`

## 授權

ISC
