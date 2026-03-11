// ===== API Helper =====
const API = {
    token: localStorage.getItem('token') || '',
    baseURL: window.location.origin,

    async request(method, path, body) {
        const opts = { method, headers: {} };
        if (this.token) opts.headers['Authorization'] = 'Bearer ' + this.token;
        if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const resp = await fetch(this.baseURL + path, opts);
        const data = await resp.json();
        if (resp.status === 401 && path !== '/auth/login' && path !== '/auth/root/otp') {
            this.token = '';
            localStorage.removeItem('token');
            showLogin();
        }
        if (!resp.ok) throw new Error(data.error || resp.statusText);
        return data;
    },
    get(path) { return this.request('GET', path); },
    post(path, body) { return this.request('POST', path, body); },
    put(path, body) { return this.request('PUT', path, body); },
    del(path, body) { return this.request('DELETE', path, body); },

    setToken(t) { this.token = t; localStorage.setItem('token', t); },
    clearToken() { this.token = ''; localStorage.removeItem('token'); }
};

// ===== Toast =====
function toast(msg, type = 'success') {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'toast ' + type;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 3000);
}

// ===== Navigation =====
function showLogin() {
    document.getElementById('page-login').classList.add('active');
    document.getElementById('dashboard').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
    document.getElementById('otp-section').classList.add('hidden');
    document.getElementById('root-setup-section').classList.add('hidden');
    document.getElementById('login-error').classList.add('hidden');
}

function showDashboard() {
    document.getElementById('page-login').classList.remove('active');
    document.getElementById('dashboard').classList.remove('hidden');
    loadCurrentUser();
    navigateTo(location.hash.slice(1) || 'users');
}

function navigateTo(page) {
    document.querySelectorAll('.page-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(el => el.classList.remove('active'));
    const target = document.getElementById('page-' + page);
    const link = document.querySelector(`.nav-link[data-page="${page}"]`);
    if (target) target.classList.add('active');
    if (link) link.classList.add('active');
    // Load data
    if (page === 'users') loadUsers();
    else if (page === 'roles') loadPolicies();
    else if (page === 'defaults') loadDefaults();
    else if (page === 'registry') loadRegistry();
    else if (page === 'settings') loadSettings();
}

// ===== Login Flow =====
let pendingRootToken = '';

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    try {
        const data = await API.post('/auth/login', { username, password });
        if (data.require_otp) {
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('otp-section').classList.remove('hidden');
            toast('请查看服务器控制台获取登录码', 'success');
        } else {
            API.setToken(data.access_token);
            showDashboard();
        }
    } catch (err) {
        const el = document.getElementById('login-error');
        el.textContent = err.message;
        el.classList.remove('hidden');
    }
});

document.getElementById('otp-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('otp-code').value;
    try {
        const data = await API.post('/auth/root/otp', { code });
        API.setToken(data.access_token);
        showDashboard();
    } catch (err) {
        toast(err.message, 'error');
    }
});

// Root setup is handled inside the dashboard settings, not on the login page.

// ===== Logout =====
document.getElementById('logout-btn').addEventListener('click', async () => {
    try { await API.post('/auth/logout'); } catch (_) { }
    API.clearToken();
    showLogin();
});

// ===== Nav links =====
document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const page = link.dataset.page;
        location.hash = page;
        navigateTo(page);
    });
});

// ===== Current User =====
async function loadCurrentUser() {
    try {
        const data = await API.get('/auth/me');
        const u = data.user;
        document.getElementById('current-user').textContent =
            `${u.username} (${u.is_root ? 'root' : u.role})`;
    } catch (_) { }
}

// ===== Users Page =====
async function loadUsers() {
    try {
        const data = await API.get('/auth/admin/users');
        const tbody = document.getElementById('users-tbody');
        tbody.innerHTML = data.users.map(u => `
            <tr>
                <td>${u.id}</td>
                <td>${u.username}</td>
                <td><span class="badge">${u.role}</span></td>
                <td><span class="badge ${u.status === 'active' ? 'badge-success' : 'badge-danger'}">${u.status}</span></td>
                <td>${u.is_root ? '✓' : ''}</td>
                <td>${new Date(u.created_at).toLocaleDateString()}</td>
                <td>
                    ${u.is_root ? '' : `<button class="btn btn-danger btn-sm" onclick="toggleUserStatus(${u.id}, '${u.status === 'active' ? 'banned' : 'active'}')">${u.status === 'active' ? '封禁' : '解封'}</button>`}
                </td>
            </tr>
        `).join('');
    } catch (err) { toast(err.message, 'error'); }
}

window.toggleUserStatus = async function (userId, status) {
    try {
        await API.put('/auth/admin/users/status', { user_id: userId, status });
        toast('用户状态已更新');
        loadUsers();
    } catch (err) { toast(err.message, 'error'); }
};

// ===== Roles/Policies Page =====
document.getElementById('add-policy-btn').addEventListener('click', () => {
    document.getElementById('add-policy-form').classList.toggle('hidden');
});

document.getElementById('submit-policy').addEventListener('click', async () => {
    const role = document.getElementById('policy-role').value;
    const object = document.getElementById('policy-object').value;
    const action = document.getElementById('policy-action').value;
    if (!role || !object || !action) return toast('请填写所有字段', 'error');
    try {
        await API.post('/api/permissions/policies', { role, object, action });
        toast('策略已添加');
        document.getElementById('add-policy-form').classList.add('hidden');
        loadPolicies();
    } catch (err) { toast(err.message, 'error'); }
});

async function loadPolicies() {
    try {
        const data = await API.get('/api/permissions/policies');
        const tbody = document.getElementById('policies-tbody');
        tbody.innerHTML = data.policies.map(p => `
            <tr>
                <td><span class="badge">${p.role}</span></td>
                <td>${p.object}</td>
                <td>${p.action}</td>
                <td><button class="btn btn-danger btn-sm" onclick="removePolicy('${p.role}','${p.object}','${p.action}')">删除</button></td>
            </tr>
        `).join('');
    } catch (err) { toast(err.message, 'error'); }
}

window.removePolicy = async function (role, object, action) {
    try {
        await API.del('/api/permissions/policies', { role, object, action });
        toast('策略已删除');
        loadPolicies();
    } catch (err) { toast(err.message, 'error'); }
};

// ===== Defaults Page =====
let currentDefaultRole = 'user';
let currentDefaults = [];

document.getElementById('load-defaults-btn').addEventListener('click', () => {
    currentDefaultRole = document.getElementById('defaults-role-select').value;
    loadDefaults();
});

document.getElementById('add-default-btn').addEventListener('click', async () => {
    const object = document.getElementById('default-object').value;
    const action = document.getElementById('default-action').value;
    if (!object || !action) return toast('请填写所有字段', 'error');
    currentDefaults.push({ role: currentDefaultRole, object, action });
    await saveDefaults();
});

async function loadDefaults() {
    try {
        const data = await API.get('/api/permissions/defaults/' + currentDefaultRole);
        currentDefaults = data.policies || [];
        renderDefaults();
    } catch (err) { toast(err.message, 'error'); }
}

function renderDefaults() {
    const tbody = document.getElementById('defaults-tbody');
    tbody.innerHTML = currentDefaults.map((p, i) => `
        <tr>
            <td><span class="badge">${p.role || currentDefaultRole}</span></td>
            <td>${p.object}</td>
            <td>${p.action}</td>
            <td><button class="btn btn-danger btn-sm" onclick="removeDefault(${i})">删除</button></td>
        </tr>
    `).join('');
}

window.removeDefault = async function (index) {
    currentDefaults.splice(index, 1);
    await saveDefaults();
};

async function saveDefaults() {
    try {
        const policies = currentDefaults.map(p => ({
            role: currentDefaultRole,
            object: p.object,
            action: p.action
        }));
        await API.put('/api/permissions/defaults/' + currentDefaultRole, { policies });
        toast('默认权限已更新');
        loadDefaults();
    } catch (err) { toast(err.message, 'error'); }
}

// ===== Registry Page =====
async function loadRegistry() {
    try {
        const modData = await API.get('/api/permissions/registry');
        const container = document.getElementById('registry-modules');
        container.innerHTML = '';

        for (const mod of (modData.modules || [])) {
            const permData = await API.get('/api/permissions/registry/' + mod);
            const perms = permData.permissions || [];

            // Group by resource
            const grouped = {};
            perms.forEach(p => {
                if (!grouped[p.resource]) grouped[p.resource] = { desc: p.description, actions: [] };
                grouped[p.resource].actions.push(p.action);
            });

            let html = `<div class="module-card"><h3><span class="nav-icon">📦</span>${mod}</h3>`;
            for (const [res, info] of Object.entries(grouped)) {
                html += `<div style="margin-bottom:0.75rem">`;
                html += `<div style="font-size:0.85rem;font-weight:600;margin-bottom:0.3rem">${mod}.${res}`;
                if (info.desc) html += ` <span style="color:var(--text-muted);font-weight:400">— ${info.desc}</span>`;
                html += `</div><div class="perm-list">`;
                info.actions.forEach(a => { html += `<span class="perm-tag">${a}</span>`; });
                html += `</div></div>`;
            }
            html += `</div>`;
            container.innerHTML += html;
        }

        if (!(modData.modules || []).length) {
            container.innerHTML = '<div class="card"><p style="color:var(--text-muted)">暂无已注册的模块</p></div>';
        }
    } catch (err) { toast(err.message, 'error'); }
}

// ===== Settings Page =====
async function loadSettings() {
    // Load user list for binding
    try {
        const data = await API.get('/auth/admin/users');
        const container = document.getElementById('bind-user-list');
        const users = (data.users || []).filter(u => !u.is_root);
        if (users.length === 0) {
            container.innerHTML = '<p style="color:var(--text-muted)">没有可绑定的用户</p>';
            return;
        }
        container.innerHTML = `<table class="data-table"><thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>操作</th></tr></thead><tbody>` +
            users.map(u => `<tr><td>${u.id}</td><td>${u.username}</td><td><span class="badge">${u.role}</span></td><td><button class="btn btn-primary btn-sm" onclick="bindRootToUser(${u.id}, '${u.username}')">绑定</button></td></tr>`).join('') +
            `</tbody></table>`;
    } catch (err) { toast(err.message, 'error'); }
}

document.getElementById('save-creds-btn').addEventListener('click', async () => {
    const password = document.getElementById('settings-password').value;
    if (!password) return toast('请输入密码', 'error');
    try {
        await API.post('/auth/root/setup', {
            action: 'set_credentials',
            username: document.getElementById('settings-username').value || '',
            password
        });
        toast('密码已保存，下次可直接使用密码登录');
    } catch (err) { toast(err.message, 'error'); }
});

window.bindRootToUser = async function (userId, username) {
    if (!confirm(`确定将 Root 权限绑定到用户 "${username}" (ID: ${userId})？`)) return;
    try {
        await API.post('/auth/root/setup', { action: 'bind_user', user_id: userId });
        toast(`Root 权限已绑定到 ${username}`);
        API.clearToken();
        showLogin();
    } catch (err) { toast(err.message, 'error'); }
};

// ===== Init =====
window.addEventListener('hashchange', () => {
    if (API.token) navigateTo(location.hash.slice(1) || 'users');
});

// Check if already logged in
if (API.token) {
    showDashboard();
} else {
    showLogin();
}
