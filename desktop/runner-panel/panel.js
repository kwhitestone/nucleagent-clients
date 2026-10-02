'use strict';
const get = (id) => document.getElementById(id);
const invoke = (command, args) => {
  if (!window.__TAURI__?.core) return Promise.reject(new Error('请从桌面客户端的“本机执行”菜单打开此页面。普通浏览器不能访问本机执行器。'));
  return window.__TAURI__.core.invoke(command, args);
};
let ready = false;
let busy = false;
const definitions = [
  { id: 'codex', label: 'Codex', version: '0.149.1' },
  { id: 'opencode', label: 'OpenCode', version: '1.18.23' },
];
const labels = { missing: '未安装', 'installed-unprobed': '文件校验通过 · 待本次协议检查', incompatible: '文件漂移 · 接单禁止', downloading: '下载中', verifying: '校验中', installing: '安装中', probing: '空会话检查中', ready: '运行时检查通过', probed: '运行时检查通过', starting: '正在启动', 'awaiting-user-confirmation': '等待网页确认绑定', bound: '已绑定', renewed: '凭据已续期', revoked: '已撤销', running: '执行中', 'awaiting-ack': '等待 Core 确认', acknowledged: 'Core 已确认' };
for (const backend of definitions) {
  const row = document.createElement('div');
  row.className = 'backend';
  const text = document.createElement('div');
  const title = document.createElement('strong');
  title.textContent = `${backend.label} ${backend.version}`;
  const status = document.createElement('p');
  status.id = `status-${backend.id}`;
  status.textContent = '待检查';
  text.append(title, status);
  const button = document.createElement('button');
  button.id = `install-${backend.id}`;
  button.type = 'button';
  button.textContent = '安装 / 重新检查';
  button.disabled = true;
  button.addEventListener('click', () => install(backend.id));
  row.append(text, button);
  get('backends').append(row);
}
function updateButtons() {
  for (const backend of definitions) get(`install-${backend.id}`).disabled = !ready || busy || !get('consent').checked;
  for (const id of ['bind', 'start', 'revoke']) get(id).disabled = !ready || busy || !get('consent').checked;
  get('stop').disabled = !busy;
}
function progress(value) {
  if (!value) return;
  get('progress-text').textContent = value.error || labels[value.state] || value.admission || value.state || '';
  get('progress').hidden = !busy;
  if (value.total > 0) {
    get('progress').max = value.total;
    get('progress').value = value.current || 0;
    get('progress-text').textContent += ` · ${Math.round((value.current || 0) / 1048576)} / ${Math.round(value.total / 1048576)} MiB`;
  } else get('progress').removeAttribute('value');
}
async function refresh() {
  try {
    const state = await invoke('runner_snapshot');
    busy = state.busy;
    if (state.doctor) {
      const doctor = state.doctor;
      ready = doctor.nativeUserReady;
      get('identity').textContent = `${doctor.identity.os} / ${doctor.identity.arch} · ${ready ? '普通用户环境检查通过' : '当前环境不可接单'}`;
      get('reason').textContent = doctor.reason || '并发上限 1；仅接受本账户下发的任务。';
    }
    for (const backend of state.backends || []) get(`status-${backend.backend}`).textContent = labels[backend.state] || backend.error || '状态未知';
    if (state.device) get('device').textContent = `设备编号：${state.device.deviceId}`;
    else if (!busy) get('device').textContent = '尚未绑定设备';
    if (state.progress?.state === 'awaiting-user-confirmation') get('binding').textContent = `在主壳任务页面确认绑定。编号：${state.progress.id}；验证码：${state.progress.userCode}`;
    else get('binding').textContent = '';
    get('history').replaceChildren();
    const latest = new Map((state.events || []).map(event => [event.conversationId, event]));
    for (const event of latest.values()) {
      const row = document.createElement('li');
      row.textContent = `任务 ${event.conversationId} · ${labels[event.state] || event.state}${event.state === 'acknowledged' ? ` · ${event.resultStatus}` : ''} `;
      try {
        const origin = new URL(get('shell-origin').value);
        if (origin.protocol === 'https:' && !origin.username && !origin.password) {
          const link = document.createElement('a');
          link.href = `${origin.origin}/chat/${Number(event.conversationId)}`;
          link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = '查看结果与产物';
          row.append(link);
        }
      } catch { /* The user can add the shell origin later. */ }
      get('history').append(row);
    }
    progress(state.progress);
    updateButtons();
  } catch (error) {
    ready = false;
    get('identity').textContent = '无法连接本机执行器';
    get('reason').textContent = String(error);
    updateButtons();
  }
}
async function install(backend) {
  if (!ready || busy || !get('consent').checked) return;
  busy = true;
  updateButtons();
  try { await invoke('runner_install', { backend }); get('progress-text').textContent = '运行时检查通过；接单仍关闭。'; }
  catch (error) { get('progress-text').textContent = String(error); }
  finally { busy = false; get('progress').hidden = true; await refresh(); }
}
get('refresh').addEventListener('click', refresh);
get('consent').addEventListener('change', updateButtons);
void refresh();
async function control(action) {
  if (action !== 'stop' && (!ready || busy || !get('consent').checked)) return;
  try {
    const operation = invoke('runner_control', { action, coreOrigin: get('core-origin').value.trim() || null, consent: get('consent').checked });
    if (action !== 'stop') busy = true;
    updateButtons();
    await operation;
  } catch (error) { get('progress-text').textContent = String(error); }
  finally { await refresh(); }
}
get('bind').addEventListener('click', () => control('bind'));
get('start').addEventListener('click', () => control('run'));
get('stop').addEventListener('click', () => control('stop'));
get('revoke').addEventListener('click', () => control('revoke'));
get('shell-origin').addEventListener('change', refresh);
setInterval(() => { if (busy) void refresh(); }, 1000);
