/**
 * auto-secret-mask — 两种模式:
 *
 * 1. 模式识别: 输入中检测常见前缀 (sk-/ghp_/AKIA...) → 替换为 $API_KEY_N
 * 2. 强匹配:   配置文件 ~/.pi/agent/extension-settings/secrets.json 提供的 { NAME: 值 },
 *              全局精确匹配 (输入/工具输出/文件内容), 替换为
 *              [API_KEY_REDACTED USE_$NAME]
 *
 * 工具执行时 $NAME → 真实值; 会话历史只保留 $NAME / 占位符。
 *
 * 配置文件格式 (~/.pi/agent/extension-settings/secrets.json):
 *   { "envFiles": ["~/.zshenv", "~/.env"] }                // 全量导入, 自动过滤系统变量
 *   { "envFiles": { "~/.zshenv": ["GH_TOKEN"] } }          // 白名单, 只导入点名变量
 * 解析 KEY=value 行 (支持 export 前缀、引号、# 注释)。
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { homedir } from "node:os";
import { mask as maskSecrets } from "./mask-core.ts";

// 优先读取 extension-settings 目录，兼容回退根目录
const PRIMARY_CONFIG_PATH = resolve(homedir(), ".pi/agent/extension-settings/secrets.json");
const FALLBACK_CONFIG_PATH = resolve(homedir(), ".pi/agent/secrets.json");
const MIN_LEN = 4; // 太短的值全局替换会误伤数字/端口等

// NAME -> 真实值（配置 + 自动检测合并）
const secrets = new Map<string, string>();
// 真实值 -> NAME
const names = new Map<string, string>();
let autoCounter = 0;

// 解析一行环境变量: export KEY="value" # comment
function parseEnvLine(line: string): [string, string] | null {
  const t = line.trim();
  if (!t || t.startsWith("#")) return null;
  const m = t.match(/^(?:export\s+)?\$?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
  if (!m) return null;
  let v = m[2].replace(/\s+#.*$/, "").trim(); // 去掉行内注释
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    v = v.slice(1, -1);
  }
  return [m[1], v];
}

// 全量导入时过滤的常见非密钥系统变量（前缀匹配）
const IGNORED_ENV = [
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "EDITOR", "VISUAL", "PWD",
  "OLDPWD", "LANG", "LANGUAGE", "LC_", "TERM", "SHLVL", "HOSTNAME", "HOST",
  "DISPLAY", "SSH_", "TMUX", "ZSH", "ZSH_", "BASH", "BASH_", "INFOPATH",
  "MANPATH", "XDG_", "DBUS_", "MAIL", "OSTYPE", "HOSTTYPE", "MACHTYPE",
  "LINES", "COLUMNS", "RANDOM", "SECONDS", "PPID", "UID", "GID", "EUID",
  "USERNAME", "GROUP", "SHELLOPTS", "BASHOPTS", "PROMPT_", "PS1", "PS2",
  "PS3", "PS4", "RPROMPT", "RPS1", "__", "_ ",
];

function isIgnoredEnv(name: string): boolean {
  return IGNORED_ENV.some((i) => (i.endsWith("_") ? name.startsWith(i) : name === i));
}

function parseEnvFile(path: string, wanted: string[] | null): Map<string, string> {
  const out = new Map<string, string>();
  const p = path.startsWith("~/") ? resolve(homedir(), path.slice(2)) : path;
  if (!existsSync(p)) {
    console.error(`[auto-secret-mask] 环境变量文件不存在: ${p}`);
    return out;
  }
  for (const line of readFileSync(p, "utf-8").split("\n")) {
    const kv = parseEnvLine(line);
    if (!kv) continue;
    const [name, value] = kv;
    if (value.length < MIN_LEN) continue;
    if (wanted) {
      if (wanted.includes(name)) out.set(name, value);
    } else if (!isIgnoredEnv(name)) {
      out.set(name, value);
    }
  }
  return out;
}

function loadConfig() {
  try {
    const configPath = existsSync(PRIMARY_CONFIG_PATH)
      ? PRIMARY_CONFIG_PATH
      : existsSync(FALLBACK_CONFIG_PATH)
        ? FALLBACK_CONFIG_PATH
        : null;
    if (!configPath) return;
    const raw = JSON.parse(readFileSync(configPath, "utf-8")) as Record<string, unknown>;
    const envFiles = raw.envFiles;
    if (Array.isArray(envFiles)) {
      // 全量导入
      for (const file of envFiles as string[]) {
        for (const [name, value] of parseEnvFile(file, null)) {
          secrets.set(name, value);
          names.set(value, name);
        }
      }
    } else if (envFiles && typeof envFiles === "object") {
      // 白名单
      for (const [file, vars] of Object.entries(envFiles as Record<string, string[]>)) {
        for (const [name, value] of parseEnvFile(file, vars)) {
          secrets.set(name, value);
          names.set(value, name);
        }
      }
    }
  } catch (err) {
    console.error(`[auto-secret-mask] 读取 secrets.json 失败: ${String(err)}`);
  }
}

function nameFor(value: string): string {
  let n = names.get(value);
  if (!n) {
    n = `API_KEY_${++autoCounter}`;
    names.set(value, n);
    secrets.set(n, value);
  }
  return n;
}

// 强匹配: 精确值 → [REDACTED: $NAME]（按值长度从长到短, 避免短值破坏长值）
function redact(text: string): string {
  let out = text;
  const sorted = [...secrets].sort((a, b) => b[1].length - a[1].length);
  for (const [name, value] of sorted) {
    out = out.replaceAll(value, `[REDACTED: $${name}]`);
  }
  return out;
}

// 模式识别 + 熵兜底 → $NAME (逻辑在 mask-core, 这里只接 nameFor 映射去重)
function mask(text: string): string {
  return maskSecrets(text, nameFor);
}

// $NAME / ${NAME} → 真实值（工具执行前）
function unmask(text: string): string {
  let out = text;
  // ① 占位符（模型可能把 [REDACTED: $NAME] 复制进参数）→ 直接还原真实值
  for (const [name, value] of secrets) out = out.replaceAll(`[REDACTED: $${name}]`, value);
  // ② 独立变量引用 → 真实值；跳过转义 \$NAME 和 $NAME 前缀/后缀（避免破坏转义和误匹配）
  for (const [name, value] of secrets) {
    out = out
      .replace(new RegExp(String.raw`(?<!\\)\$${name}(?![A-Za-z0-9_])`, "g"), value)
      .replace(new RegExp(String.raw`(?<!\\)\$\{${name}\}`, "g"), value);
  }
  return out;
}

function mapStringsInPlace<T>(v: T, fn: (s: string) => string): T {
  if (typeof v === "string") return fn(v) as T;
  if (Array.isArray(v)) {
    for (let i = 0; i < v.length; i++) v[i] = mapStringsInPlace(v[i], fn);
    return v;
  }
  if (v && typeof v === "object") {
    for (const k of Object.keys(v as Record<string, unknown>)) {
      (v as Record<string, unknown>)[k] = mapStringsInPlace((v as Record<string, unknown>)[k], fn);
    }
    return v;
  }
  return v;
}

function mapStrings<T>(v: T, fn: (s: string) => string): T {
  if (typeof v === "string") return fn(v) as T;
  if (Array.isArray(v)) return v.map((x) => mapStrings(x, fn)) as T;
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) o[k] = mapStrings(x, fn);
    return o as T;
  }
  return v;
}

function redactDeep<T>(v: T): T {
  if (typeof v === "string") return redact(v) as T;
  if (Array.isArray(v)) return v.map(redactDeep) as T;
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) o[k] = redactDeep(x);
    return o as T;
  }
  return v;
}

export default function (pi: ExtensionAPI) {
  loadConfig();

  // 1. 用户输入: 先模式识别成 $NAME, 再强匹配替换成占位符（历史存的就是这个）
  pi.on("input", async (event) => {
    const text = redact(mask(event.text));
    if (text === event.text) return { action: "continue" };
    return { action: "transform", text };
  });

  // 2. 工具执行前: $NAME → 真实值（就地修改 event.input, 重新赋值会断开内部引用）
  pi.on("tool_call", async (event) => {
    mapStringsInPlace(event.input, unmask);
  });

  // 3. 工具输出 (含 details): 真实值 → 占位符（兜底）
  pi.on("tool_result", async (event) => {
    // 先模式识别+熵检测 (把新暴露的密钥加进 secrets Map), 再强匹配替换成占位符。
    // 早期版本只跑 redact → 工具输出里首次出现的密钥永远不被脱敏 (真实测试暴露)。
    const content = event.content.map((c) =>
      c.type === "text"
        ? { ...c, text: redact(maskSecrets(c.text, nameFor)) }
        : c
    );
    const patch: { content?: typeof content; details?: unknown } = { content };
    if (event.details) {
      patch.details = redactDeep(mapStrings(event.details, (s) => maskSecrets(s, nameFor)));
    }
    return patch;
  });

  // 4. 把使用规则注入系统提示: 模型被明确告知脱敏占位符的用法
  pi.on("before_agent_start", async (event) => {
    if (secrets.size === 0) return;
    const placeholderList = [...secrets.keys()].map((k) => `[REDACTED: $${k}]`).join(", ");
    const exampleName = [...secrets.keys()][0];
    event.systemPrompt +=
      `\n\n[auto-secret-mask] The following sensitive values in this session have been masked: ${placeholderList}.\n` +
      `When referencing or passing these secrets to tools, you can use either the exact placeholder [REDACTED: $${exampleName}], ` +
      `or the variable $${exampleName} / \${${exampleName}}. ` +
      `The system will automatically restore the real values before tool execution. ` +
      `Do not attempt to inspect, guess, or ask for the original values.`;
  });
}
