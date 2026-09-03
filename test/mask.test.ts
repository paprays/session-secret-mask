// 冒烟测试: 密钥规则识别 + 上下文熵兜底 + 误报排除。逻辑任何一处破坏都会让断言挂。
// 运行: npx tsx test/mask.test.ts
// 注意: 假密钥夹具用字符串拼接构造, 使源文件里不存在完整密钥模式,
//       避免 GitHub Push Protection 把测试夹具误判为真实密钥而拦截推送。
import { mask } from "../mask-core.ts";

let counter = 0;
const names = new Map<string, string>();
const nameFor = (v: string): string => {
  if (!names.has(v)) names.set(v, `API_KEY_${++counter}`);
  return names.get(v)!;
};

const mk = (t: string) => mask(t, nameFor);
const assert = (cond: boolean, msg: string) => {
  if (!cond) {
    console.error("FAIL:", msg);
    process.exitCode = 1;
  }
};

// 假密钥夹具: 运行时拼接, 源文件不含完整模式
const FAKE = {
  openai: "sk-proj-" + "AbCdEfGh1234567890AbCdEfGh1234567890",
  gh: "ghp_" + "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  aws: "AKIA" + "1234567890ABCDEF",
  slack: "xoxb-" + "123456789-abcdefghijklmnopqrst",
  stripe: "sk_live_" + "5098abcDfGhJkLmNoPqRsTuV",
  privkey: "-----BEGIN " + "PRIVATE KEY-----",
};

// 该被脱敏的密钥
assert(mk("token: " + FAKE.openai).includes(FAKE.openai) === false, "OpenAI 新格式");
assert(mk("GH token = " + FAKE.gh).includes(FAKE.gh) === false, "GitHub PAT");
assert(mk(FAKE.aws) !== FAKE.aws, "AWS");
assert(mk(FAKE.slack) !== FAKE.slack, "Slack");
assert(mk(FAKE.stripe) !== FAKE.stripe, "Stripe");
assert(mk(FAKE.privkey) !== FAKE.privkey, "私钥块");
assert(mk('api_key = "' + FAKE.openai + '"') !== 'api_key = "' + FAKE.openai + '"', "api key 赋值");

// 不该误伤的
assert(mk("The quick brown fox jumps over the lazy dog today") === "The quick brown fox jumps over the lazy dog today", "普通英文");
assert(mk("/home/user/projects/awesome-app") === "/home/user/projects/awesome-app", "路径");
assert(mk("commit abcdef0123456789abcdef0123456789abcdef01") === "commit abcdef0123456789abcdef0123456789abcdef01", "Git SHA");
assert(mk("11111111-2222-3333-4444-555555555555") === "11111111-2222-3333-4444-555555555555", "UUID");
assert(mk("your_api_key = placeholder1234567890") === "your_api_key = placeholder1234567890", "占位符");
assert(mk("今天天气很好我们去公园散步聊天真的很开心") === "今天天气很好我们去公园散步聊天真的很开心", "中文散文");
assert(mk("你去看看我cpa里nhh的配置，直接用对应的baseurl和apikey去测试") === "你去看看我cpa里nhh的配置，直接用对应的baseurl和apikey去测试", "中英混排无空格");
assert(mk("还有我的pi插件 auto secret mask我输入什么他都把输入变成变量 hash1 这是测试内容 api key") === "还有我的pi插件 auto secret mask我输入什么他都把输入变成变量 hash1 这是测试内容 api key", "包含secret/hash/key的自然语言聊天不误判");

if (!process.exitCode) console.log("mask-core 冒烟测试全部通过");
