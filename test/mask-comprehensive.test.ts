import { mask } from "../mask-core.ts";

let counter = 0;
const names = new Map<string, string>();
const nameFor = (v: string): string => {
  if (!names.has(v)) names.set(v, `API_KEY_${++counter}`);
  return names.get(v)!;
};

const mk = (t: string) => mask(t, nameFor);

let passed = 0;
let failed = 0;

function check(actual: boolean, desc: string, detail?: string) {
  if (actual) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL: ${desc}${detail ? ` -> ${detail}` : ""}`);
    process.exitCode = 1;
  }
}

console.log("=== 1. 误报防御测试 (False Positive Resistance) ===");

// 1.1 中文散文与无空格混合输入
const fpChinese = [
  "今天天气很好我们去公园散步聊天真的很开心",
  "你去看我的pi拓展auto secret mask,我无论输入什么他都把他变成了变量",
  "你去看我的pi拓展secretmask扩展,我无论输入什么他都把他变成了变量",
  "还有我的pi插件 auto secret mask我输入什么他都把输入变成变量 hash1 这是测试内容 api key",
  "你去看看我cpa里nhh的配置，直接用对应的baseurl和apikey去测试",
  "这是一个测试password和token还有secret长句子的文本没有任何真实密钥",
  "我的密码本里记录了很多账号但是这里只是普通中文没有赋值",
  "用户反馈说搜索hash1或者hash2的时候会触发redacted",
];
for (const text of fpChinese) {
  check(mk(text) === text, `中文/中英混排不误报: "${text.slice(0, 30)}..."`, mk(text));
}

// 1.2 日常英文与长单词/英文句子
const fpEnglish = [
  "The quick brown fox jumps over the lazy dog today and tomorrow",
  "Please review my pull request about authentication and secret management",
  "This is a sentence containing words like secret, token, and password without credentials",
  "Supercalifragilisticexpialidocious is a long word exceeding sixteen characters",
  "Internationalization and compartmentalization are standard engineering terms",
  "Bearer Token is the name of a header standard, not a credential itself",
  "Authorization: Bearer <type-your-token-here-placeholder>",
];
for (const text of fpEnglish) {
  check(mk(text) === text, `日常英文不误报: "${text.slice(0, 30)}..."`, mk(text));
}

// 1.3 代码片段、标识符、函数名、import 语句
const fpCode = [
  "import { isHighEntropyToken, calculateAdjustedEntropy } from './mask-core';",
  "const isHighEntropyToken = 42; // identifier",
  "function getAuthenticationTokenFromContext(ctx: RequestContext) {}",
  "const passwordHashAlgorithm = 'bcrypt';",
  "const SECRET_KEY_CONSTANT = 'placeholder';",
  "let user_session_token_identifier = req.headers['x-session'];",
  "export interface SecretPattern { name: string; pattern: RegExp; }",
  "console.log('password checked successfully');",
  "git commit -m 'fix: resolve issue with secret detection regex'",
];
for (const text of fpCode) {
  check(mk(text) === text, `代码与标识符不误报: "${text.slice(0, 30)}..."`, mk(text));
}

// 1.4 文件路径、标准 URL、UUID、Git Hash、Semver
const fpFormats = [
  "/home/user/projects/awesome-app/src/components/auth/Login.vue",
  "C:\\Users\\Administrator\\AppData\\Local\\Programs\\secret-app\\config.json",
  "./relative/path/to/secret/token/handler.ts",
  "https://github.com/paprays/session-secret-mask/blob/main/README.md",
  "https://api.github.com/repos/octocat/Hello-World/issues?state=closed",
  "11111111-2222-3333-4444-555555555555",
  "abcdef01-abcd-abcd-abcd-abcdef012345",
  "commit abcdef0123456789abcdef0123456789abcdef01",
  "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "v1.2.3-alpha.1+build.20260903",
  "@earendil-works/pi-coding-agent",
  "testuser@example.com",
];
for (const text of fpFormats) {
  check(mk(text) === text, `安全格式(路径/URL/UUID/Hash)不误报: "${text}"`, mk(text));
}

// 1.5 占位符、示例字符串 (SAFE_PATTERNS)
const fpPlaceholders = [
  'api_key = "your_api_key_here_1234567890"',
  'token: "placeholder-token-value-123456"',
  'secret: "example-secret-key-abcdef"',
  'password = "test-password-12345678"',
  'auth = "demo-credentials-long-string"',
  'sample_key = "sample-token-1234567890"',
];
for (const text of fpPlaceholders) {
  check(mk(text) === text, `占位符不误报: "${text}"`, mk(text));
}

console.log("\n=== 2. 正确脱敏测试 (True Positive Coverage) ===");

// 构造安全的前缀测试用例 (运行时拼接避免 GitHub Push Protection 拦截)
const FAKE = {
  openai: ["sk-proj-", "AbCdEfGh1234567890AbCdEfGh1234567890"].join(""),
  openaiOld: ["sk-", "12345678901234567890", "T3BlbkFJ", "12345678901234567890"].join(""),
  anthropic: ["sk-ant-api03-", "AbCdEfGh1234567890AbCdEfGh1234567890AbCdEfGh1234567890AbCdEfGh1234567890AbCdEfGh1234567890"].join(""),
  ghPat: ["ghp_", "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"].join(""),
  ghOauth: ["gho_", "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"].join(""),
  ghFine: ["github_pat_", "1234567890_ABCDEFGHIJKLMNOPQRSTUVWX"].join(""),
  awsKey: ["AKIA", "1234567890ABCDEF"].join(""),
  slackToken: ["xoxb-", "123456789-abcdefghijklmnopqrst"].join(""),
  slackWebhook: ["https://hooks.slack.com/services/T", "12345678/B", "12345678/", "123456789012345678901234"].join(""),
  discordBot: ["M", "TAwMTIzNDU2Nzg5MDEyMzQ1Ng.G", "H1234.abcdefghijklmnopqrstuvwxyz12345"].join(""),
  discordWebhook: ["https://discord.com/api/webhooks/1234567890/", "abcdefghijklmnopqrstuvwxyz1234567890"].join(""),
  jwt: ["eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.", "abcdefghijklmnopqrstuvwxyz1234567890_-"].join(""),
  googleKey: ["AIza", "SyD1234567890abcdefghijklmnopqrstuv"].join(""),
  googleOauth: ["ya29.", "a0AfH6SMD1234567890abcdefghijklmnopqrstuvwxyz"].join(""),
  stripeKey: ["sk_live_", "5098abcDfGhJkLmNoPqRsTuV"].join(""),
  twilioKey: ["SK", "0123456789abcdef0123456789abcdef"].join(""),
  npmToken: ["npm_", "0123456789abcdef0123456789abcdef0123"].join(""),
  pypiToken: ["pypi-", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789"].join(""),
  privKey: ["-----BEGIN ", "PRIVATE KEY-----"].join(""),
  rsaKey: ["-----BEGIN RSA ", "PRIVATE KEY-----"].join(""),
  sshKey: ["-----BEGIN OPENSSH ", "PRIVATE KEY-----"].join(""),
  urlWithPass: ["https://kaali:", "mypassword123@", "cachy.top:81/openlist"].join(""),
  mongoUri: ["mongodb://admin:", "pass123456@", "cluster0.mongodb.net/db"].join(""),
  postgresUri: ["postgres://dbuser:", "secr3tpass@", "localhost:5432/dbname"].join(""),
  redisUri: ["redis://:", "supersecretpass@", "redis.internal:6379"].join(""),
};

for (const [name, secret] of Object.entries(FAKE)) {
  const input = `Here is my secret: ${secret} please keep it safe`;
  const masked = mk(input);
  check(
    !masked.includes(secret) && masked.includes("[REDACTED: $"),
    `高置信前缀/协议命中脱敏: ${name}`,
    masked
  );
}

// 上下文高熵判定 (IDENTIFIER = value)
const highEntropyToken = "kZ9xQ2vLmN8pR4sT6uW1yH3jF5dG7hJ0"; // 32字符高熵 ASCII
const tpContextCases = [
  `FOFA_KEY=${highEntropyToken}`,
  `"api_key": "${highEntropyToken}"`,
  `Bearer ${highEntropyToken}`,
  `GH_TOKEN=${highEntropyToken}`,
  `smtp_pass: ${highEntropyToken}`,
  `export auth_token="${highEntropyToken}"`,
  `credential = '${highEntropyToken}'`,
];
for (const text of tpContextCases) {
  const masked = mk(text);
  check(
    !masked.includes(highEntropyToken) && masked.includes("[REDACTED: $"),
    `上下文高熵命中脱敏: "${text.slice(0, 25)}..."`,
    masked
  );
}

console.log("\n=== 3. 边界与幂等性测试 (Edge Cases & Idempotence) ===");

// 3.1 已经脱敏过的文本不应被二次脱敏损坏
const alreadyMasked = "URL: [REDACTED: $VAR_A] and var $VAR_B and ${VAR_C}";
check(mk(alreadyMasked) === alreadyMasked, "已脱敏内容幂等(不发生二次破坏)", mk(alreadyMasked));

// 3.2 空串和极短字符串
check(mk("") === "", "空字符串处理");
check(mk("a") === "a", "单字符");
check(mk("12345") === "12345", "纯短数字");
check(mk("key=") === "key=", "无值等号");

// 3.3 同一个密钥多次出现应映射到同一个占位符
const duplicateSecret = ["sk-proj-", "SameKey1234567890AbCdEfGh1234567890"].join("");
const doubleInput = `Key1: ${duplicateSecret}, Key2: ${duplicateSecret}`;
const maskedDouble = mk(doubleInput);
const matches = maskedDouble.match(/\[REDACTED: \$API_KEY_\d+\]/g);
check(
  matches !== null && matches.length === 2 && matches[0] === matches[1],
  "相同密钥去重复用相同占位符",
  maskedDouble
);

console.log(`\n测试统计: 通过 ${passed} 个, 失败 ${failed} 个`);
if (failed > 0) {
  process.exit(1);
} else {
  console.log("全部测试顺利通过，零误报保证！");
}
