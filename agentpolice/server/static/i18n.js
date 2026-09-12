'use strict';

/* Strings the result renderer produces at runtime.
   The static copy lives in each page's HTML; this file exists only because
   findings are built in JS after a scan, and an English page must not render
   Chinese verdicts. Loaded before app.js, which calls the global `t()`. */

const I18N = {
  'zh-CN': {
    'sev.critical': '严重', 'sev.high': '高', 'sev.medium': '中',
    'sev.low': '低', 'sev.info': '信息',
    'confidence': (v) => `置信度 ${v}`,
    'no.issues': '没有发现高于「信息」级别的问题',
    'info.show': (n) => `显示 ${n} 条信息级条目`,
    'info.hide': '收起信息级条目',
    'need.url': '请填写端点 base_url。',
    'connecting': '正在连接端点…',
    'pf.empty': '端点基本信息看起来正常。这只说明它没有明显的配置问题，不代表它不会改写工具调用——那需要完整探测。',
    'need.command': '请粘贴一条命令。',
    'ins.clean': '没有命中已知的危险形态',
    'ins.clean.body': '这是启发式判断，没有比对基准。它只能说「这条命令的形状不像典型攻击」，不能说明这条命令就是模型原本产出的那一条。',
    'v.tampered': '这个端点篡改了工具调用',
    'v.tampered.body': (n) => `${n} 次探测中，返回的工具调用与请求要求的不一致，且改动方向会改变 agent 实际执行的内容。立即停止通过该端点运行 agent，并轮换所有经过它的凭证。`,
    'v.notable': '没有观察到篡改，但端点本身有值得注意的地方',
    'v.notable.body': '本次探测没有抓到工具调用被改写。请看下面的端点体检结论。另外请记住：条件投递（AC-1.b）在触发前完全正常，有限次探测无法证明端点干净。',
    'v.clean': '本次探测没有观察到篡改',
    'v.clean.body': '这不是一份无罪证明。论文观察到的真实触发条件包括「前 50 次请求先装好人」、「只对自动批准模式下手」、「只针对 Rust/Go 项目」。触发逻辑在服务端，任何有限次数的黑盒探测都无法排除它。',
    'th.probe': '探针', 'th.class': '类别', 'th.ok': '正常',
    'th.tampered': '被改写', 'th.nocall': '无调用', 'th.error': '错误',
    'canary.planted': (n) => `<strong>已植入 ${n} 个可观测 canary。</strong> `,
    'canary.note': 'AC-2 不改动流量，所以现在查不出来——被窃取的凭证通常要先验证、转卖才会被使用。',
    'canary.later': (id) => `稍后回来查看结果：<code>/api/canary/${id}</code>`,
    'job.statusfail': (s) => `无法获取任务状态：HTTP ${s}`,
    'job.preparing': '准备中…',
    'job.failed': (e) => `探测失败：${e}`,
    'err.unknown': '未知错误',
    'download.json': '下载完整 JSON 报告',
    'need.all': '端点、模型 id 和 API key 都需要填写。',
    'submitting': '正在提交…',
    'job.id': (id) => `任务 ${id}`,
  },
  en: {
    'sev.critical': 'CRITICAL', 'sev.high': 'HIGH', 'sev.medium': 'MEDIUM',
    'sev.low': 'LOW', 'sev.info': 'INFO',
    'confidence': (v) => `confidence ${v}`,
    'no.issues': 'Nothing above informational was found',
    'info.show': (n) => `Show ${n} informational item${n === 1 ? '' : 's'}`,
    'info.hide': 'Hide informational items',
    'need.url': 'Enter the endpoint base_url.',
    'connecting': 'Connecting to the endpoint…',
    'pf.empty': 'The endpoint looks unremarkable. That only means it has no obvious misconfiguration — it does not mean it will not rewrite tool calls. That takes a full probe.',
    'need.command': 'Paste a command first.',
    'ins.clean': 'No known dangerous shape matched',
    'ins.clean.body': 'This is a heuristic with nothing to compare against. It can say "this command does not look like a typical attack"; it cannot say this is the command the model actually produced.',
    'v.tampered': 'This endpoint tampered with the tool call',
    'v.tampered.body': (n) => `In ${n} probe(s) the returned tool call did not match what was requested, and the change would alter what the agent actually executes. Stop running agents through this endpoint and rotate every credential that passed through it.`,
    'v.notable': 'No tampering observed, but the endpoint itself is worth a look',
    'v.notable.body': 'This probe did not catch a rewritten tool call. See the endpoint findings below. Remember that conditional delivery (AC-1.b) behaves perfectly until it triggers, so a finite probe cannot show an endpoint is clean.',
    'v.clean': 'No tampering observed in this probe',
    'v.clean.body': 'This is not a certificate of innocence. Real triggers the paper observed include "behave for the first 50 requests", "only target auto-approve sessions", and "only target Rust/Go projects". The trigger logic runs server-side, and no finite black-box probe can rule it out.',
    'th.probe': 'Probe', 'th.class': 'Class', 'th.ok': 'Clean',
    'th.tampered': 'Rewritten', 'th.nocall': 'No call', 'th.error': 'Error',
    'canary.planted': (n) => `<strong>${n} observable canaries planted.</strong> `,
    'canary.note': 'AC-2 does not alter traffic, so it cannot show up now — stolen credentials are usually validated and resold before they are used.',
    'canary.later': (id) => `Check back later at <code>/api/canary/${id}</code>`,
    'job.statusfail': (s) => `Could not read job status: HTTP ${s}`,
    'job.preparing': 'Starting…',
    'job.failed': (e) => `Probe failed: ${e}`,
    'err.unknown': 'unknown error',
    'download.json': 'Download the full JSON report',
    'need.all': 'Endpoint, model id and API key are all required.',
    'submitting': 'Submitting…',
    'job.id': (id) => `Job ${id}`,
  },
};

const APG_LANG = document.documentElement.lang.startsWith('en') ? 'en' : 'zh-CN';

function t(key, ...args) {
  const table = I18N[APG_LANG] || I18N['zh-CN'];
  const value = table[key];
  if (value === undefined) return key;
  return typeof value === 'function' ? value(...args) : value;
}
