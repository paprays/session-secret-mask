// 自检: bun run mask-core.test.ts
// 验证修复后的 mask() 不再误伤普通文本, 仍能脱敏真实密钥。
import { mask } from "./mask-core.ts";

let n = 0;
const nameFor = (v: string) => `$API_KEY_${++n}`;

const KV = "kZ9xQ2vLmN8pR4sT6uW1yH3jF5dG7hJ0kL2mN4p"; // 40字符高熵

const cases: [string, boolean /* 期望被替换 */][] = [
  // 用户日常输入: 必须原样保留
  ["你去看我的pi拓展auto secret mask,我无论输入什么他都把他变成了变量", false],
  ["你去看我的pi拓展secretmask扩展,我无论输入什么他都把他变成了变量", false], // 无空格中英粘连长 token(真实触发模式)
  ["auto-secret-mask扩展 把输入变成变量", false],
  ["const isHighEntropyToken = 42; // 代码标识符", false],
  ["the quick brown fox jumps over the lazy dog", false],
  ["请帮我 review 一下 secretmask/index.ts 这个文件", false],
  ["Bearer Token 是源码里的名字字段, 不该被匹配", false],
  // 密钥上下文: 必须替换
  [`FOFA_KEY=${KV}`, true],
  [`"api_key": "${KV}"`, true],
  [`Bearer ${KV}`, true],
  [`GH_TOKEN=${KV}`, true],
  // 已知前缀模式: 行为不变
  ["ghp_123456789012345678901234567890123456", true],
  ["OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890", true],
];

let fail = 0;
for (const [input, expectMasked] of cases) {
  const out = mask(input, nameFor);
  const masked = out !== input;
  const ok = masked === expectMasked;
  if (!ok) fail++;
  console.log(`${ok ? "PASS" : "FAIL"} | masked=${masked} | ${input.slice(0, 50)}`);
  if (!ok) console.log(`       -> ${out.slice(0, 60)}`);
}
console.log(fail === 0 ? "\nALL PASS" : `\n${fail} FAILED`);
process.exit(fail === 0 ? 0 : 1);
