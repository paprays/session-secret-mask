// --------------------------------------------------------------------------
// 模式识别规则集: 移植自 opencode-secrets-protect (MIT, jscheel) 的
// SECRET_PATTERNS —— 手写高置信前缀 + 熵兜底 + 误报排除表, 思路与 gitleaks
// 官方一致 (关键词前缀 / 熵门槛 / allowlist)。
//
// 纯函数模块: 不依赖 Node/pi, 便于单测。
// --------------------------------------------------------------------------

export interface SecretPattern {
  name: string;
  pattern: RegExp;
  // 高置信前缀 (如 ghp_) 跳过误报排除; 否则 (KEY=value 类) 用 SAFE_PATTERNS 复核
  highConfidence?: boolean;
}

export const secretPatterns: SecretPattern[] = [
  { name: "AWS Access Key ID", pattern: /\bAKIA[0-9A-Z]{16}\b/, highConfidence: true },
  { name: "AWS Secret Access Key", pattern: /(?:aws)?_?(?:secret)?_?(?:access)?_?key['"\s:=]+['"]?[0-9a-zA-Z/+]{40}['"]?/i },
  { name: "GitHub App Token", pattern: /\b(?:ghu|ghs)_[0-9a-zA-Z]{36}\b/, highConfidence: true },
  { name: "GitHub OAuth Token", pattern: /\bgho_[0-9a-zA-Z]{36}\b/, highConfidence: true },
  { name: "GitHub PAT", pattern: /\bghp_[0-9a-zA-Z]{36}\b/, highConfidence: true },
  { name: "GitHub Fine-Grained Token", pattern: /\bgithub_pat_[0-9a-zA-Z_]{22,}\b/, highConfidence: true },
  { name: "GitLab PAT", pattern: /\bglpat-[0-9a-zA-Z\-_]{20,}\b/, highConfidence: true },
  { name: "GitLab Runner Token", pattern: /\bglrt-[0-9a-zA-Z_\-]{20,}\b/, highConfidence: true },
  { name: "Slack Token", pattern: /\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b/, highConfidence: true },
  { name: "Slack Webhook URL", pattern: /https?:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8,}\/B[a-zA-Z0-9_]{8,}\/[a-zA-Z0-9_]{24}/, highConfidence: true },
  { name: "JWT", pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/, highConfidence: true },
  { name: "Google API Key", pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/, highConfidence: true },
  { name: "Google OAuth Token", pattern: /\bya29\.[0-9A-Za-z\-_]+\b/, highConfidence: true },
  { name: "Google Service Account", pattern: /"type"\s*:\s*["']service_account["']/, highConfidence: true },
  { name: "Stripe Secret Key", pattern: /\bsk_live_[0-9a-zA-Z]{24,}\b/, highConfidence: true },
  { name: "Stripe Restricted Key", pattern: /\brk_live_[0-9a-zA-Z]{24,}\b/, highConfidence: true },
  { name: "Twilio API Key", pattern: /\bSK[a-z0-9]{32}\b/, highConfidence: true },
  { name: "SendGrid API Key", pattern: /\bSG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{40,}\b/, highConfidence: true },
  { name: "Discord Bot Token", pattern: /\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b/, highConfidence: true },
  { name: "Discord Webhook URL", pattern: /https?:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_\-]+/, highConfidence: true },
  // OpenAI/Anthropic 新旧两种格式都覆盖
  { name: "Anthropic API Key", pattern: /\bsk-ant-api[0-9]{2}-[a-zA-Z0-9\-_]{80,}\b/, highConfidence: true },
  { name: "OpenAI API Key", pattern: /\bsk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}\b/, highConfidence: true },
  { name: "OpenAI API Key (New Format)", pattern: /\bsk-(?:proj-)?[a-zA-Z0-9\-_]{40,}\b/, highConfidence: true },
  { name: "NPM Token", pattern: /\bnpm_[a-zA-Z0-9]{36}\b/, highConfidence: true },
  { name: "PyPI Token", pattern: /\bpypi-[a-zA-Z0-9_\-]{50,}\b/, highConfidence: true },
  { name: "Heroku API Key", pattern: /[hH]eroku[a-zA-Z0-9\-_]*['"\s:=]+['"]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}['"]?/ },
  { name: "RSA Private Key", pattern: /-----BEGIN RSA PRIVATE KEY-----/, highConfidence: true },
  { name: "OpenSSH Private Key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/, highConfidence: true },
  { name: "DSA Private Key", pattern: /-----BEGIN DSA PRIVATE KEY-----/, highConfidence: true },
  { name: "EC Private Key", pattern: /-----BEGIN EC PRIVATE KEY-----/, highConfidence: true },
  { name: "PGP Private Key", pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/, highConfidence: true },
  { name: "Generic Private Key", pattern: /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/, highConfidence: true },
  { name: "MongoDB URI", pattern: /mongodb(?:\+srv)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/, highConfidence: true },
  { name: "PostgreSQL URI", pattern: /postgres(?:ql)?:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/, highConfidence: true },
  { name: "MySQL URI", pattern: /mysql:\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/, highConfidence: true },
  { name: "Redis URI", pattern: /redis:\/\/[^\s'"]*:[^\s'"]+@[^\s'"]+/, highConfidence: true },
  { name: "Password in URL", pattern: /[a-zA-Z]{3,10}:\/\/[^/\s:@]{3,20}:[^/\s:@]{3,20}@[^\s'"]+/, highConfidence: true },
  // 低置信: KEY=value 赋值, 需要误报排除表兜底
  { name: "Bearer Token", pattern: /[Bb]earer\s+[a-zA-Z0-9\-._~+/]{10,}=*/ },
  { name: "Basic Auth Header", pattern: /[Bb]asic\s+[a-zA-Z0-9+/]{20,}={0,2}/ },
  { name: "API Key Assignment", pattern: /(?:api[_-]?key|apikey|api[_-]?secret)['"\s:=]+['"]?[a-zA-Z0-9\-._]{20,}['"]?/i },
];

// 误报排除: 命中即视为安全内容 (URL/路径/邮箱/UUID/semver/Git SHA/占位符)
export const SAFE_PATTERNS: RegExp[] = [
  /^https?:\/\/[a-zA-Z0-9.-]+(?:\/[a-zA-Z0-9./_\-?&=#%]*)?$/, // URL 无凭据
  /^\.\.?\/[a-zA-Z0-9_\-./]+$/,                                // 相对路径
  /^\/[a-zA-Z0-9_\-./]+$/,                                     // 绝对路径
  /^[a-zA-Z]:\\[a-zA-Z0-9_\-\.\\/]+$/,                         // Windows 路径
  /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,        // 邮箱
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/, // UUID
  /^v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?(?:\+[a-zA-Z0-9.]+)?$/,  // semver
  /^(?:xxx+|your[_-]?(?:api[_-]?)?key|placeholder|example|test|demo|sample)/i, // 占位符
  /^[0-9a-f]{40}$/i, // Git SHA-1
  /^[0-9a-f]{64}$/i, // SHA-256
  /^@[a-z0-9-]+\/[a-z0-9-]+$/, // npm 作用域包
];

export function isSafeContent(s: string): boolean {
  return SAFE_PATTERNS.some((re) => re.test(s));
}

// ------ 熵检测: 移植自 opencode-secrets-protect/src/entropy.ts (MIT) ------
const ENTROPY_THRESHOLD = 4.5;
const MIN_TOKEN_LEN = 16;

function shannonEntropy(data: string): number {
  if (data.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of data) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const c of freq.values()) {
    const p = c / data.length;
    e -= p * Math.log2(p);
  }
  return e;
}

function calculateAdjustedEntropy(data: string): number {
  const base = shannonEntropy(data);
  const len = data.length;
  if (len === 0) return 0;
  let up = 0, low = 0, letters = 0, digits = 0, symbols = 0, caseSwitches = 0;
  let prevUpper = false;
  for (let i = 0; i < len; i++) {
    const code = data.charCodeAt(i);
    if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
      letters++;
      const isUpper = code >= 65 && code <= 90;
      if (isUpper) {
        up++;
        if (i > 0 && !prevUpper) caseSwitches++;
        prevUpper = true;
      } else {
        low++;
        if (i > 0 && prevUpper) caseSwitches++;
        prevUpper = false;
      }
    } else if (code >= 48 && code <= 57) {
      digits++;
    } else if (data[i] !== " " && data[i] !== "\t" && data[i] !== "\n") {
      symbols++;
    }
  }
  let boost = 0;
  if (up > 0 && low > 0 && letters > 0) boost += (caseSwitches / letters) * 2.0 * 2.5;
  if (symbols > 0) boost += (symbols / len) * 1.5;
  if (digits > 0) boost += digits / len;
  return base + boost;
}

// 需含至少一个 ASCII 字母/数字才判熵 —— 排除纯中文/日文等非密钥高熵散文,
// 真实密钥 (API key/token) 必然含 ASCII 字母数字。这是对 opencode 源自 code
// 扫描场景、未适配聊天散文的诚实修正。
function isHighEntropyToken(s: string): boolean {
  if (s.length < MIN_TOKEN_LEN) return false;
  if (!/[a-zA-Z0-9]/.test(s)) return false;
  return calculateAdjustedEntropy(s) > ENTROPY_THRESHOLD && !isSafeContent(s);
}

// 模式识别 + 熵兜底, 把命中的密钥替换为占位符。
// nameFor(value) → 占位符 (如 $API_KEY_1), 由调用方管理去重映射。
export function mask(text: string, nameFor: (v: string) => string): string {
  let out = text;
  for (const sp of secretPatterns) {
    out = out.replace(sp.pattern, (m) => {
      // 低置信 (KEY=value 类) 只对「值」做误报排除: 取 = / : 之后的部分, 与
      // SAFE_PATTERNS (占位符/示例等) 比对, 避免把 api_key = placeholder 误伤。
      if (!sp.highConfidence) {
        const afterSep = m.replace(/^[^=:]*[=:]\s*/, "").replace(/^['"]+|['"]+$/g, "");
        if (isSafeContent(afterSep)) return m;
      }
      return `$${nameFor(m)}`;
    });
  }
  // 熵兜底: 只对「密钥赋值上下文」里的高熵 token 生效 —— IDENTIFIER = value /
  // "ident": "value" / Bearer token 等, 且 IDENTIFIER 含密钥特征词。没有关键词
  // 上下文的普通文本 (代码标识符、英文词、中文夹英文、URL) 一律不判 —— 之前不加
  // 上下文门槛, 把正常输入都替换成了 $API_KEY_N (这就是「输入什么都变变量」的根因)。
  // 等价于 opencode 的 split + findHighEntropyToken, 但加上了关键词上下文门槛。
  const ctxRe = new RegExp(
    `(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]{2,})[\\s'":=]+([^\\s.,;:'"=\\[\\]{}()<>|/\\\\]{${MIN_TOKEN_LEN},})`,
    "g"
  );
  out = out.replace(ctxRe, (m, key, val) =>
    /(?:token|secret|pass(?:word|wd)?|api[_-]?key|apikey|access[_-]?key|auth(?:orization)?|credential|bearer|fofa|smtp|code|hash|sign)/i.test(key) &&
    isHighEntropyToken(val)
      ? m.replace(val, `$${nameFor(val)}`)
      : m
  );
  return out;
}
