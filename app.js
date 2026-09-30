/* ============================================================
   CYPHER SECURITY — DASHBOARD FRONTEND
   ============================================================ */

const $ = sel => document.querySelector(sel);
const appEl = $('#app');
const FALLBACK_AVATAR = `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(`
    <svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
        <rect width="512" height="512" rx="128" fill="#2a1010"/>
        <circle cx="256" cy="210" r="92" fill="#8f1d1d"/>
        <path d="M112 420c18-100 72-150 144-150s126 50 144 150" fill="#d63d3d"/>
    </svg>
`)}`;

let BOT = null;
let BOT_LOADED_AT = Date.now();
let ME = null;
let SERVERS = null;
let ADMIN_GUILD_IDS = new Set();
let GUILD = null;
let currentTab = 'overview';
let currentGuildId = null;
let botStatsTimer = null;
let uptimeTicker = null;
let AUTH_READY = false;
let AUTH_QUICK = false;
let SKIP_AUTO_LOGIN = false;
let REVOKED = false;

/* ============================================================
   TOAST
   ============================================================ */

function toast(message, type = 'ok') {
    const wrap = $('#toast-wrap');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = message;
    wrap.appendChild(t);
    setTimeout(() => t.remove(), 3600);
}

async function api(url, options = {}) {
    const res = await fetch(url, {
        headers: { 'Content-Type': 'application/json' },
        ...options
    });
    let data = null;
    try { data = await res.json(); } catch {}
    if (!res.ok || !data?.ok) {
        throw new Error(data?.error || 'حدث خطأ، أعد المحاولة.');
    }
    return data;
}

function fmt(ms) {
    const value = Math.max(0, Number(ms) || 0);
    const s = Math.floor(value / 1000);
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d} يوم ${h} ساعة`;
    if (h > 0) return `${h} ساعة ${m} دقيقة`;
    if (m > 0) return `${m} دقيقة`;
    return 'أقل من دقيقة';
}

function fmtFull(value) {
    return new Intl.NumberFormat('ar-EG').format(Math.max(0, Number(value) || 0));
}

function fmtNum(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return String(n);
}

function escapeHtml(str) {
    return String(str == null ? '' : str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// توحيد النص للمقارنة (مثل ديسكورد: يشيل التشكيل وي lowercase)
function normalizeText(value) {
    return String(value == null ? '' : value)
        .normalize('NFKD')
        .replace(/[\u064B-\u0652\u0640]/g, '')
        .replace(/\s+/g, ' ')
        .trim()
        .toLowerCase();
}

function iconFor(value) {
    const url = String(value || '').trim();
    if (url.startsWith('/')) return url;
    if (/^https?:\/\//i.test(url) || /^data:image\//i.test(url)) return url;
    return FALLBACK_AVATAR;
}

document.addEventListener('error', event => {
    if (!(event.target instanceof HTMLImageElement)) return;
    if (event.target.src === FALLBACK_AVATAR) return;
    event.target.src = FALLBACK_AVATAR;
}, true);

/* ============================================================
   HELPERS: UI BUILDERS
   ============================================================ */

function channelName(type, name) {
    if (type === 4) return `📁 ${name}`;
    if (type === 2) return `🔊 ${name}`;
    return `# ${name}`;
}

/* ============================================================
   ROUTES
   ============================================================ */

async function boot() {
    stopLandingTimers();

    const hash = location.hash || '';
    const errorAt = hash.indexOf('login-error=');

    try {
        const [botRes, meRes, authRes, sessionRes] = await Promise.allSettled([
            api('/api/bot'),
            api('/api/me'),
            api('/api/auth/status'),
            api('/api/session')
        ]);

        if (botRes.status === 'fulfilled' && botRes.value?.bot) {
            BOT = botRes.value.bot;
            BOT_LOADED_AT = Date.now();
            applyBotBranding();
        }

        ME = meRes.status === 'fulfilled' ? meRes.value.user : null;
        AUTH_READY = authRes.status === 'fulfilled' ? Boolean(authRes.value?.ready) : false;
        AUTH_QUICK = authRes.status === 'fulfilled' ? Boolean(authRes.value?.quick) : false;
        REVOKED = meRes.status === 'rejected' && /إلغاء تفعيل/.test(meRes.reason?.message || '');

        // بيانات الجلسة: المستخدم + السيرفرات المفلترة بصلاحية Administrator
        if (sessionRes.status === 'fulfilled' && sessionRes.value?.user) {
            ME = sessionRes.value.user;
            SERVERS = sessionRes.value.guilds || [];
            ADMIN_GUILD_IDS = new Set(sessionRes.value.adminGuilds || []);
        }

        let loginError = '';
        if (errorAt !== -1) {
            loginError = decodeURIComponent(hash.slice(errorAt + 12).split('&')[0]);
            history.replaceState(null, '', location.pathname);
        }

        // مسجل دخول: يدخل على الواجهة الرئيسية (مو على طول قائمة السيرفرات)
        if (ME) {
            if (hash.startsWith('#server/')) {
                await renderServer(hash.split('/')[1]);
                return;
            }
            if (hash === '#servers') {
                await renderServers();
                return;
            }
            history.replaceState(null, '', '#home');
            await renderHome();
            return;
        }

        if (loginError) { renderLanding(loginError); return; }

        if (REVOKED) {
            renderLanding('تم إلغاء تفعيل حسابك من الداشبورد. كلّم صاحب البوت.');
            return;
        }

        // ما فيه جلسة: ندخله على طول (محاولة صامتة = فورية)
        if (AUTH_READY && !SKIP_AUTO_LOGIN) {
            location.replace(AUTH_QUICK ? '/api/auth/quick' : '/api/auth/login?silent=1');
            return;
        }

        renderLanding();
    } catch {
        renderLanding();
    }
}

window.addEventListener('hashchange', () => {
    boot();
});

window.addEventListener('popstate', () => {
    boot();
});

/* ============================================================
   LANDING (بطاقة تعريفية + زر ابدأ الآن)
   ============================================================ */

// اسم البوت الحقيقي من ديسكورد — ونرجع للافتراضي لو ما وصل
function botName(n = BOT || {}) {
    return String(n?.username || n?.tag || 'Cypher Security').trim() || 'Cypher Security';
}

function renderLanding(loginError = '') {
    const n = BOT || {};
    const startLabel = ME ? '▶️ ابدأ الآن — سيرفراتك' : '▶️ ابدأ الآن';

    const userNote = ME
        ? `<div class="hero-user-note">مسجل دخول كـ <b>${escapeHtml(ME.username)}</b></div>`
        : `<div class="hero-user-note">اضغط "ابدأ الآن" وبتطلع لك على طول قائمة سيرفراتك — بدون آيدي وبدون كود وبدون باسوورد.</div>`;

    const notReady = !ME && !AUTH_READY
        ? `<div class="login-warning">⚠️ تسجيل الدخول غير مُفعّل على البوت بعد.<br>أضف <b>CLIENT_ID</b> و <b>CLIENT_SECRET</b> في ملف <b>.env</b> ثم أعد تشغيل البوت.</div>`
        : '';


    const errorBox = loginError
        ? `<div class="login-warning">❌ ${escapeHtml(loginError)}</div>`
        : '';

    appEl.innerHTML = `
        <div class="hero">
            <div class="hero-badge">🛡️ <b>${escapeHtml(botName(n))}</b> — نظام حماية و إدارة</div>

            <div class="hero-avatar-wrap">
                <img id="bot-avatar" class="hero-avatar pulse" src="${escapeHtml(iconFor(n.avatar))}" alt="صورة البوت">
            </div>

            <div>
                <h1 class="hero-title">بوت حماية وسيستم<br>لـ <span class="red">سيرفرك</span></h1>
                <p class="hero-sub">تحكم كامل من الداشبورد: إشراف، حماية، ترحيب، تكتات، سجلات — بضغطة زر بدون ما تحتاج أوامر سلاش.</p>
            </div>

            <div class="hero-actions">
                <button id="start-button" type="button" class="btn btn-primary btn-cta btn-start" ${ME || AUTH_READY ? '' : 'disabled'}>${startLabel}</button>
                ${n.inviteUrl ? `<a class="btn btn-ghost" href="${escapeHtml(n.inviteUrl)}" target="_blank" rel="noopener noreferrer">إضافة البوت إلى سيرفر</a>` : ''}
            </div>
            ${userNote}
            ${notReady}
            ${errorBox}

            <div class="hero-stats" aria-live="polite">
                <div class="stat-card">
                    <div id="stat-servers" class="num">${n.ready ? fmtFull(n.servers) : '0'}</div>
                    <div class="lbl">عدد السيرفرات</div>
                </div>
                <div class="stat-card">
                    <div id="stat-members" class="num">${n.ready ? fmtFull(n.members) : '0'}</div>
                    <div class="lbl">إجمالي الأعضاء</div>
                </div>
                <div class="stat-card stat-uptime-card">
                    <div id="stat-uptime" class="num">${fmt(n.uptimeMs)}</div>
                    <div class="lbl">مدة أونلاين البوت</div>
                </div>
            </div>

            <div id="bot-status" class="bot-status">
                <span id="bot-status-dot" class="status-dot"></span>
                <span id="bot-status-text">${n.ready ? 'البوت متصل الآن' : 'جاري الاتصال بالبوت'}</span>
                ${n.ping !== null && n.ping !== undefined ? `<span class="status-separator">•</span><span>${fmtFull(n.ping)} ms</span>` : ''}
            </div>
        </div>
        <div class="footer-note">لوحة تحكم ${escapeHtml(botName(n))} © ${new Date().getFullYear()}</div>
    `;

    bindLandingActions();
    startLandingTimers();
}

function bindLandingActions() {
    const startButton = $('#start-button');
    if (!startButton) return;

    startButton.addEventListener('click', () => {
        if (ME) {
            history.replaceState(null, '', '#servers');
            renderServers();
            return;
        }

        // دخول على طول — وضع مباشر (بضغطة وحدة) أو ديسكورد (صامت)
        location.href = AUTH_QUICK ? '/api/auth/quick' : '/api/auth/login?silent=1';
    });
}

function stopLandingTimers() {
    if (botStatsTimer) clearInterval(botStatsTimer);
    if (uptimeTicker) clearInterval(uptimeTicker);
    botStatsTimer = null;
    uptimeTicker = null;
}

function landingUptimeMs() {
    const base = Number(BOT?.uptimeMs) || 0;
    if (!BOT?.ready) return 0;
    return base + Math.max(0, Date.now() - BOT_LOADED_AT);
}

function updateLandingStats() {
    if (!$('#start-button')) return;

    const n = BOT || {};
    const servers = $('#stat-servers');
    const members = $('#stat-members');
    const uptime = $('#stat-uptime');
    const avatar = $('#bot-avatar');
    const statusDot = $('#bot-status-dot');
    const statusText = $('#bot-status-text');

    if (servers) servers.textContent = fmtFull(n.servers);
    if (members) members.textContent = fmtFull(n.members);
    if (uptime) uptime.textContent = fmt(landingUptimeMs());

    if (avatar) {
        let avatarUrl = iconFor(n.avatar);
        if (n.avatarVersion && avatarUrl.startsWith('/')) {
            avatarUrl += `?v=${encodeURIComponent(n.avatarVersion)}`;
        }
        if (avatar.getAttribute('src') !== avatarUrl) avatar.src = avatarUrl;
    }

    if (statusDot) statusDot.classList.toggle('online', Boolean(n.ready));
    if (statusText) statusText.textContent = n.ready ? 'البوت متصل الآن' : 'جاري الاتصال بالبوت';
}

async function refreshBotStats() {
    try {
        const data = await api('/api/bot');
        BOT = data.bot;
        BOT_LOADED_AT = Date.now();
        applyBotBranding();
        updateLandingStats();
    } catch {}
}

// اسم البوت في عنوان التبويب + الفافيكون
function applyBotBranding() {
    const name = botName(BOT);

    if (!name) return;

    document.title = `${name} | لوحة التحكم`;

    let icon = document.querySelector('link[rel="icon"]');

    if (!icon) {
        icon = document.createElement('link');
        icon.rel = 'icon';
        document.head.appendChild(icon);
    }

    icon.href = String(BOT?.avatar || '/api/bot/avatar');
}

function startLandingTimers() {
    stopLandingTimers();
    updateLandingStats();
    uptimeTicker = setInterval(updateLandingStats, 1000);
    botStatsTimer = setInterval(refreshBotStats, 5000);
}

/* ============================================================
   SERVERS LIST
   ============================================================ */

let STATS = null;

async function renderHome() {
    stopLandingTimers();

    let data = null;
    try {
        data = await api('/api/session');
    } catch (e) {
        if (/غير مسجل/.test(e.message || '')) { renderLanding(); return; }
        renderLanding(e.message);
        return;
    }

    if (!data?.user) { renderLanding(); return; }

    ME = data.user;
    SERVERS = data.guilds || [];
    ADMIN_GUILD_IDS = new Set(data.adminGuilds || []);
    STATS = data.stats || null;

    const bot = data.bot || BOT || {};
    const s = STATS || {};

    const guilds = SERVERS;
    const preview = guilds.slice(0, 8);

    appEl.innerHTML = `
        <div class="home-page">
            <div class="home-topbar">
                <div class="page-user">
                    <img src="${escapeHtml(iconFor(ME.avatar))}">
                    <span>${escapeHtml(ME.username || ME.globalName || '')}</span>
                </div>
                <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <span class="bot-pill ${bot.ready ? 'ok' : ''}">● ${escapeHtml(bot.username || 'البوت')} ${bot.ready ? 'متصل' : 'يتصل...'}</span>
                    <button type="button" class="btn btn-ghost btn-sm" data-action="refresh-servers">🔄 تحديث</button>
                    <button type="button" class="btn btn-danger btn-sm" data-action="logout">تسجيل الخروج ←</button>
                </div>
            </div>

            <div class="home-hero">
                <div class="home-hero-text">
                    <h1 class="home-title">أهلاً <span class="red">${escapeHtml(ME.globalName || ME.username || '')}</span> 👋</h1>
                    <p class="home-sub">من هنا تبدأ — اضغط <b>ابدأ الآن</b> وبتطلع على كل سيرفراتك اللي عندك فيها صلاحية <b>Admin</b> أو رتبة <b>${escapeHtml(data.staffRoleName || 'ستريتر')}</b>.</p>
                    <div class="home-actions">
                        <button type="button" class="btn btn-primary btn-cta btn-start" data-action="go-servers">▶️ ابدأ الآن</button>
                        ${bot.inviteUrl
                            ? `<a class="btn btn-ghost" href="${escapeHtml(bot.inviteUrl)}" target="_blank" rel="noopener noreferrer">➕ إضافة البوت إلى سيرفر</a>`
                            : ''}
                    </div>
                </div>
                <img class="home-bot-avatar" src="${escapeHtml(bot.avatar || iconFor(bot.avatar))}" alt="البوت">
            </div>

            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-icon">🛡️</div>
                    <div class="stat-value">${fmtNum(s.guilds ?? guilds.length)}</div>
                    <div class="stat-label">سيرفر أنت داخله</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">👥</div>
                    <div class="stat-value">${fmtNum(s.members ?? 0)}</div>
                    <div class="stat-label">عضو في كل سيرفراتك</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🟢</div>
                    <div class="stat-value">${fmtNum(s.online ?? 0)}</div>
                    <div class="stat-label">أونلاين الحين</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">⚙️</div>
                    <div class="stat-value">${fmtNum(s.managedGuilds ?? 0)}</div>
                    <div class="stat-label">سيرفر تقدر تديره</div>
                </div>
            </div>

            <div class="home-section-head">
                <h2>سيرفراتك</h2>
                ${guilds.length > preview.length
                    ? `<button type="button" class="btn btn-ghost btn-sm" data-action="go-servers">عرض الكل (${guilds.length}) ←</button>`
                    : ''}
            </div>

            ${
                guilds.length === 0
                    ? `<div class="empty-state">ما فيه سيرفرات تقدر تديرها حالياً.<br>تأكد من أن عندك رتبة <b>${escapeHtml(data.staffRoleName || 'ستريتر')}</b> أو صلاحية <b>Admin</b>، أو أضف البوت لسيرفرك من الزر فوق.</div>`
                    : `<div class="servers-grid">
                        ${preview.map(g => `
                            <button type="button" class="server-card" data-action="open-server" data-server-id="${g.id}">
                                <div class="server-card-head">
                                    <img src="${escapeHtml(iconFor(g.icon))}">
                                    ${ADMIN_GUILD_IDS.has(g.id) ? '<span class="server-card-badge" title="صلاحية Administrator">👑</span>' : ''}
                                </div>
                                <div class="server-card-body">
                                    <h3>${escapeHtml(g.name)}</h3>
                                    <p>👥 ${fmtNum(g.memberCount ?? g.approximate_member_count)} عضو</p>
                                    ${g.approximate_presence_count
                                        ? `<p style="color:var(--green)">🟢 ${fmtNum(g.approximate_presence_count)} أونلاين</p>`
                                        : ''}
                                </div>
                            </button>
                        `).join('')}
                    </div>`
            }
        </div>
    `;
}

async function renderServers() {
    stopLandingTimers();
    try {
        // بيانات الجلسة (المستخدم + السيرفرات المفلترة بصلاحية Administrator)
        let data = await api('/api/session');

        // احتياط: لو الجلسة ناقصة نكمل من /api/me + /api/servers
        if (!data?.user) {
            const me = await api('/api/me');
            ME = me.user;
            data = await api('/api/servers');
            data.guilds = data.guilds || [];
        }

        ME = data.user;
        SERVERS = data.guilds || [];
        ADMIN_GUILD_IDS = new Set(data.adminGuilds || []);

        appEl.innerHTML = `
            <div class="servers-page">
                <div class="page-head">
                    <div>
                        <h1 class="page-title">🛡️ لوحة التحكم</h1>
                        <div style="color:var(--muted);font-size:13px;margin-top:4px">اختر سيرفراً لإدارته — تظهر لك سيرفراتك التي تملك فيها صلاحية <b>Admin</b> أو رتبة <b>${escapeHtml(data.staffRoleName || 'ستريتر')}</b>.</div>
                    </div>
                    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                        <div class="page-user">
                            <img src="${escapeHtml(iconFor(data.user.avatar))}">
                            <span>${escapeHtml(data.user.username || data.user.globalName || '')}</span>
                        </div>
                        <button type="button" class="btn btn-ghost btn-sm" data-action="refresh-servers">🔄 تحديث القائمة</button>
                        <button type="button" class="btn btn-danger btn-sm" data-action="logout">تسجيل الخروج ←</button>
                    </div>
                </div>

                ${
                    SERVERS.length === 0
                        ? `<div class="empty-state">لا توجد سيرفرات متاحة لك حالياً.<br>تأكد من أنك تملك رتبة <b>${escapeHtml(data.staffRoleName || 'موظف إدارة')}</b> أو صلاحية Admin في السيرفرات التي يوجد فيها البوت.</div>`
                        : `<div class="servers-grid">
                            ${SERVERS.map(s => `
                                <button type="button" class="server-card" data-action="open-server" data-server-id="${s.id}">
                                    <div class="server-card-head">
                                        <img src="${escapeHtml(iconFor(s.icon))}">
                                        ${ADMIN_GUILD_IDS.has(s.id) ? '<span class="server-card-badge" title="صلاحية Administrator">👑</span>' : ''}
                                    </div>
                                    <div class="server-card-body">
                                        <h3>${escapeHtml(s.name)}</h3>
                                        <p>👥 ${fmtNum(s.memberCount)} عضو</p>
                                        ${s.boostCount ? `<p style="color:var(--yellow)">✨ Boost x${s.boostCount}</p>` : ''}
                                    </div>
                                </button>
                            `).join('')}
                        </div>`
                }
            </div>
        `;
    } catch (e) {
        if (e.message.includes('غير مسجل')) { renderLanding(); return; }
        toast(e.message, 'err');
        renderLanding();
    }
}

async function refreshServers() {
    toast('جاري تحديث قائمة السيرفرات...');
    try {
        const data = await api('/api/session?refresh=1');
        SERVERS = data.guilds || [];
        ADMIN_GUILD_IDS = new Set(data.adminGuilds || []);
        STATS = data.stats || null;
        if (location.hash === '#servers') await renderServers();
        else await renderHome();
        toast('تم تحديث قائمة السيرفرات');
    } catch (e) {
        toast(e.message, 'err');
    }
}

async function logout() {
    try {
        await api('/api/logout', { method: 'POST' });
    } finally {
        ME = null;
        SERVERS = null;
        GUILD = null;
        currentGuildId = null;
        SKIP_AUTO_LOGIN = true;
        history.replaceState(null, '', location.pathname);
        renderLanding();
    }
}

/* ============================================================
   SERVER DASHBOARD
   ============================================================ */

const TABS = [
    { id: 'overview', label: 'نظرة عامة', icon: '🏠' },
    { id: 'embed', label: 'إيمبد', icon: '📩' },
    { id: 'protection', label: 'الحماية', icon: '🛡️' },
    { id: 'welcome', label: 'الترحيب', icon: '👋' },
    { id: 'tickets', label: 'التكتات', icon: '🎫' },
    { id: 'logs', label: 'السجل', icon: '📜' },
    { id: 'dashlogs', label: 'سجل الداشبورد', icon: '🗒️' },
    { id: 'autoresponses', label: 'الردود التلقائية', icon: '🤖' },
    { id: 'shortcuts', label: 'الاختصارات', icon: '⚡' },
    { id: 'levels', label: 'المستويات', icon: '🏆' },
    { id: 'autorole', label: 'الرتبة التلقائية', icon: '🎭' },
    { id: 'whitelist', label: 'الوايت ليست', icon: '🟢' }
];

async function renderServer(guildId) {
    stopLandingTimers();
    const switchedGuild = currentGuildId !== guildId;
    currentGuildId = guildId;
    try {
        const data = await api(`/api/server/${guildId}`);
        GUILD = data;

        // اختصارات + أسماء الوايت ليست محفوظة لكل سيرفر على حدة
        if (switchedGuild) {
            INVITE_STATE.loaded = false;
            INVITE_STATE.invites = [];
            WL_NAMES = {};
        }

        // ما عنده صلاحية الوايت ليست + كان على التبويب = ارجعه للنظرة العامة
        if (!data.canManageWhitelist && currentTab === 'whitelist') currentTab = 'protection';

        renderServerShell(data);
        renderTab(currentTab);
    } catch (e) {
        console.error('Dashboard server render failed:', e);
        toast(e.message, 'err');
        if (e.message.includes('غير مسجل')) renderLanding();
        else renderServers();
    }
}

function renderServerShell(data) {
    const g = data.guild;
    // 🔒 تبويب الوايت ليست: راعي البوت أو راعي السيرفر فقط
    const visibleTabs = TABS.filter(t => t.id !== 'whitelist' || data.canManageWhitelist);

    const tabs = visibleTabs.map(t => `
        <button type="button" class="tab ${currentTab === t.id ? 'active' : ''}" data-action="switch-tab" data-tab="${t.id}">
            <span class="icon">${t.icon}</span> ${t.label}
        </button>
    `).join('');

    appEl.innerHTML = `
        <div class="dash">
            <div class="dash-bar">
                <div class="dash-bar-title">
                    <img src="${escapeHtml(iconFor(g.icon))}">
                    <div>
                        <h2>${escapeHtml(g.name)}</h2>
                        <small>${fmtNum(g.memberCount)} عضو • ${g.boostCount ? `✨ Boost x${g.boostCount} • ` : ''}${g.id}</small>
                    </div>
                </div>
                <div class="dash-actions">
                    <button type="button" class="btn btn-ghost btn-sm" data-action="show-servers">↩ القائمة</button>
                    <button type="button" class="btn btn-danger btn-sm" data-action="logout">تسجيل الخروج</button>
                </div>
            </div>
            <div class="dash-body">
                <div class="tabs">${tabs}</div>
                <div class="panel" id="panel">...</div>
            </div>
        </div>
    `;
}

function switchTab(tab) {
    currentTab = tab;
    document.querySelectorAll('.tab').forEach(el => {
        el.classList.toggle('active', el.dataset.tab === tab);
    });
    renderTab(tab);
}

function panelHTML(html) {
    $('#panel').innerHTML = html;
}

/* ============================================================
   TAB RENDERERS
   ============================================================ */

function renderTab(tab) {
    switch (tab) {
        case 'overview': return renderOverview();
        case 'embed': return renderEmbed();
        case 'protection': return renderProtection();
        case 'welcome': return renderWelcome();
        case 'tickets': return renderTickets();
        case 'logs': return renderLogs();
        case 'dashlogs': return renderDashLogs();
        case 'autoresponses': return renderAutoResponses();
        case 'shortcuts': return renderShortcuts();
        case 'levels': return renderLevels();
        case 'autorole': return renderAutoRole();
        case 'whitelist': return renderWhitelist();
    }
}

/* ---------- OVERVIEW ---------- */

function renderOverview() {
    const g = GUILD.guild;
    const s = GUILD.settings;
    const prot = s.protections || {};

    const enabledCount = Object.values(prot).filter(p => p && p.enabled).length;

    // الاسم القديم `memberSearch` كان يحجب دالة memberSearch فتصير
    // `memberSearch is not a function` عند أول ضغطة مفتاح
    const searchCard = `
        <div class="panel-card">
            <h3>🔍 بحث عن عضو</h3>
            <div class="search-box">
                <input id="ov-search" placeholder="اكتب اسم العضو...">
            </div>
            <div class="members-results" id="ov-results"></div>
        </div>`;

    panelHTML(`
        <div class="panel-card">
            <h3>${escapeHtml(g.name)}</h3>
            <div class="form-grid">
                <div class="stat-card" style="background:var(--bg-2)"><div class="num">${fmtNum(g.memberCount)}</div><div class="lbl">الأعضاء</div></div>
                <div class="stat-card" style="background:var(--bg-2)"><div class="num" style="color:var(--green)">${enabledCount} / ${Object.keys(prot).length}</div><div class="lbl">حمايات مفعّلة</div></div>
                <div class="stat-card" style="background:var(--bg-2)"><div class="num" style="color:${s.welcome.enabled ? 'var(--green)' : 'var(--muted)'}">${s.welcome.enabled ? 'ON' : 'OFF'}</div><div class="lbl">الترحيب</div></div>
                <div class="stat-card" style="background:var(--bg-2)"><div class="num" style="color:${s.tickets?.enabled ? 'var(--green)' : 'var(--muted)'}">${s.tickets?.enabled ? 'ON' : 'OFF'}</div><div class="lbl">التكتات</div></div>
            </div>
        </div>
        ${searchCard}
    `);

    $('#ov-search').oninput = debounce(async e => {
        const q = e.target.value.trim();
        await memberSearch('ov-results', q, 'في السيرفر');
    }, 250);
}

let debounceTimer;
function debounce(fn, ms) {
    return (...args) => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => fn(...args), ms);
    };
}

async function memberSearch(elId, query, label) {
    const el = $('#' + elId);
    if (!el) return;
    if (!query) { el.innerHTML = '<div style="color:var(--muted);font-size:13px">اكتب للبحث عن عضو...</div>'; return; }

    try {
        const data = await api(`/api/server/${currentGuildId}/members?q=${encodeURIComponent(query)}`);
        if (!data.members.length) {
            el.innerHTML = '<div style="color:var(--muted);font-size:13px">لا توجد نتائج.</div>';
            return;
        }

        el.innerHTML = data.members.map(m => `
            <div class="item">
                <div class="grow member-row">
                    <img src="${escapeHtml(iconFor(m.avatar))}">
                    <div class="meta">
                        <b>${escapeHtml(m.username)}</b>
                        <small>${m.id}</small>
                    </div>
                </div>
                <div class="member-act">
                    <button type="button" class="btn btn-ghost btn-sm" data-action="quick-action" data-command="ban" data-user-id="${m.id}">🔨 Ban</button>
                    <button type="button" class="btn btn-ghost btn-sm" data-action="quick-action" data-command="kick" data-user-id="${m.id}">👢 Kick</button>
                    <button type="button" class="btn btn-ghost btn-sm" data-action="quick-action" data-command="jail" data-user-id="${m.id}">🔒 سجن</button>
                </div>
            </div>
        `).join('');
    } catch (err) {
        el.innerHTML = `<div style="color:var(--red-bright);font-size:13px">${escapeHtml(err.message)}</div>`;
    }
}

async function quickAction(action, userId) {
    const reason = prompt(`السبب لـ ${action}? (اتركه فارغاً إن أردت)`);
    try {
        const data = await api(`/api/server/${currentGuildId}/action`, {
            method: 'POST',
            body: JSON.stringify({ action, userId, reason: reason || undefined })
        });
        toast(data.message || '✅ تم التنفيذ');
    } catch (err) {
        toast(err.message, 'err');
    }
}

/* ---------- EMBED ---------- */

// أكواد الألوان الجاهزة (أسماؤها + أكوادها)
const EMBED_COLORS = [
    { name: 'أحمر', hex: '#ED4245' },
    { name: 'أخضر', hex: '#57F287' },
    { name: 'أزرق', hex: '#5865F2' },
    { name: 'أصفر', hex: '#FEE75C' },
    { name: 'برتقالي', hex: '#F57C00' },
    { name: 'وردي', hex: '#EB459E' },
    { name: 'بنفسجي', hex: '#9B59B6' },
    { name: 'سماوي', hex: '#1ABC9C' },
    { name: 'رمادي', hex: '#95A5A6' },
    { name: 'أسود', hex: '#23272A' }
];

// تحويل #RRGGBB أو RRGGBB إلى رقم عشري (Discord يفرض 0xRRGGBB)
function hexToInt(hex) {
    const clean = String(hex || '').replace('#', '').trim();
    if (!/^[0-9a-fA-F]{6}$/.test(clean)) return null;
    return parseInt(clean, 16);
}

// جمع حقول الإيمبد من الكارت (اسم / قيمة / inline)
function collectEmbedFields() {
    const rows = [...document.querySelectorAll('#embed-fields .embed-field-row')];
    const fields = [];

    for (const row of rows) {
        const name = row.querySelector('[data-ef="name"]').value.trim();
        const value = row.querySelector('[data-ef="value"]').value.trim();
        const inline = row.querySelector('[data-ef="inline"]').checked;

        if (!name || !value) continue;
        fields.push({ name: name.slice(0, 256), value: value.slice(0, 1024), inline });
    }

    return fields;
}

function embedFieldsHTML(fields = []) {
    if (!fields.length) {
        return `
            <div class="embed-field-row form-grid" style="align-items:end">
                <div class="form-field"><label>اسم الحقل</label><input data-ef="name" placeholder="العنوان"></div>
                <div class="form-field" style="grid-column:span 2"><label>القيمة</label><input data-ef="value" placeholder="النص"></div>
                <div class="form-field">
                    <label class="check-inline"><input type="checkbox" data-ef="inline"> على نفس السطر</label>
                    <button type="button" class="btn btn-danger btn-sm" data-action="embed-field-remove">🗑️</button>
                </div>
            </div>`;
    }

    return fields.map(f => `
        <div class="embed-field-row form-grid" style="align-items:end">
            <div class="form-field"><label>اسم الحقل</label><input data-ef="name" value="${escapeHtml(f.name || '')}"></div>
            <div class="form-field" style="grid-column:span 2"><label>القيمة</label><input data-ef="value" value="${escapeHtml(f.value || '')}"></div>
            <div class="form-field">
                <label class="check-inline"><input type="checkbox" data-ef="inline" ${f.inline ? 'checked' : ''}> على نفس السطر</label>
                <button type="button" class="btn btn-danger btn-sm" data-action="embed-field-remove">🗑️</button>
            </div>
        </div>`).join('');
}

function renderEmbed() {
    const textChannels = GUILD.channels.filter(c => c.type === 0);

    panelHTML(`
        <div class="panel-card">
            <h3>📩 إرسال إيمبد</h3>
            <div class="section-note">اختر اللون من الأزرار أو اكتب كوده يدوياً — المعاينة تحت تتحدث فوراً.</div>

            <div class="form-grid">
                <div class="form-field">
                    <label>القناة</label>
                    <select id="embed-channel">
                        ${textChannels.map(c => `<option value="${c.id}">${channelName(0, c.name)}</option>`).join('') || '<option value="">لا توجد قناة كتابية</option>'}
                    </select>
                </div>
                <div class="form-field"><label>العنوان</label><input id="embed-title" placeholder="العنوان (اختياري)"></div>
            </div>

            <div class="form-field" style="margin-top:12px">
                <label>الوصف (مطلوب)</label>
                <textarea id="embed-desc" placeholder="نص الإيمبد..."></textarea>
            </div>

            <div class="form-field" style="margin-top:12px">
                <label>🎨 كود اللون</label>
                <div class="color-picker" id="embed-color-presets">
                    ${EMBED_COLORS.map(c => `
                        <button type="button" class="color-swatch" title="${c.name} ${c.hex}" data-color="${c.hex}" style="background:${c.hex}"></button>
                    `).join('')}
                </div>
                <input id="embed-color" placeholder="#ED4245" style="margin-top:8px" maxlength="7">
                <div id="embed-color-error" style="color:var(--red-bright);font-size:12px;margin-top:4px"></div>
            </div>

            <div class="form-grid" style="margin-top:12px">
                <div class="form-field"><label>رابط صورة كبيرة</label><input id="embed-image" placeholder="https://..."></div>
                <div class="form-field"><label>رابط صورة مصغرة</label><input id="embed-thumb" placeholder="https://..."></div>
                <div class="form-field"><label>الفوتر</label><input id="embed-footer" placeholder="نص أسفل الإيمبد"></div>
                <div class="form-field"><label>رابط عند الضغط</label><input id="embed-url" placeholder="https://..."></div>
                <div class="form-field"><label>اسم صاحب الإيمبد</label><input id="embed-author" placeholder="اختياري"></div>
                <div class="form-field"><label>أيقونة صاحب الإيمبد</label><input id="embed-author-icon" placeholder="https://..."></div>
            </div>

            <div class="form-field" style="margin-top:12px">
                <label>الحقول (Fields)</label>
                <div id="embed-fields">${embedFieldsHTML()}</div>
                <div style="margin-top:8px">
                    <button type="button" class="btn btn-ghost btn-sm" data-action="embed-field-add">➕ إضافة حقل</button>
                </div>
            </div>

            <div class="form-field" style="margin-top:12px">
                <label>👁️ معاينة</label>
                <div id="embed-preview"></div>
            </div>

            <div style="margin-top:12px">
                <button type="button" class="btn btn-primary" data-action="embed">📤 إرسال</button>
            </div>
        </div>
    `);

    const colorInput = $('#embed-color');
    colorInput.value = EMBED_COLORS[0].hex;

    const update = () => {
        renderEmbedPreview(colorInput.value);
        validateEmbedColor(colorInput.value);
    };

    ['embed-title', 'embed-desc', 'embed-image', 'embed-thumb', 'embed-footer', 'embed-url', 'embed-author', 'embed-author-icon']
        .forEach(id => {
            const el = $('#' + id);
            if (el) el.addEventListener('input', update);
        });

    colorInput.addEventListener('input', update);

    $('#embed-fields').addEventListener('input', update);

    $('#embed-color-presets').addEventListener('click', e => {
        const swatch = e.target.closest('.color-swatch');
        if (!swatch) return;
        colorInput.value = swatch.dataset.color;
        update();
    });

    update();
}

function validateEmbedColor(hex) {
    const el = $('#embed-color-error');
    if (!el) return true;
    if (hex && hexToInt(hex) === null) {
        el.textContent = 'كود اللون غير صحيح — لازم #RRGGBB (مثال #ED4245)';
        return false;
    }
    el.textContent = '';
    return true;
}

function renderEmbedPreview(hex) {
    const el = $('#embed-preview');
    if (!el) return;

    const int = hexToInt(hex);
    const color = int === null ? 0xED4245 : int;
    const safeColor = `#${color.toString(16).padStart(6, '0').toUpperCase()}`;

    const val = id => ($('#' + id)?.value || '').trim();

    const title = val('embed-title');
    const description = escapeHtml(val('embed-desc')) || '<span style="color:var(--muted)">اكتب الوصف…</span>';
    const footer = val('embed-footer');
    const image = val('embed-image');
    const thumbnail = val('embed-thumb');
    const author = val('embed-author');
    const authorIcon = val('embed-author-icon');
    const url = val('embed-url');

    let fields = collectEmbedFields();
    if (!fields.length) fields = [{ name: 'حقل', value: 'قيمة الحقل', inline: true }];

    const style = `background:${safeColor}22;border-right:4px solid ${safeColor};border-radius:6px;padding:12px 14px;direction:rtl;text-align:right`;

    el.innerHTML = `
        <div style="${style}">
            ${author ? `<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
                ${authorIcon ? `<img src="${escapeHtml(authorIcon)}" style="width:24px;height:24px;border-radius:50%">` : ''}
                <b style="font-size:13px">${escapeHtml(author)}</b>
            </div>` : ''}
            ${title ? `<div style="font-weight:700;margin-bottom:6px">${escapeHtml(title)}</div>` : ''}
            <div style="font-size:13px;white-space:pre-wrap;line-height:1.6">${description}</div>
            ${fields.length ? `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:10px">
                ${fields.map(f => `
                    <div style="flex:${f.inline ? '1 1 45%' : '1 1 100%'};background:#ffffff0d;border-radius:5px;padding:8px 10px">
                        <div style="font-size:12px;opacity:.85">${escapeHtml(f.name)}</div>
                        <div style="font-size:13px">${escapeHtml(f.value)}</div>
                    </div>`).join('')}
            </div>` : ''}
            ${thumbnail ? `<img src="${escapeHtml(thumbnail)}" style="width:70px;height:70px;object-fit:cover;border-radius:6px;margin-top:10px">` : ''}
            ${image ? `<img src="${escapeHtml(image)}" style="max-width:100%;border-radius:6px;margin-top:10px;display:block">` : ''}
            ${footer ? `<div style="font-size:11px;opacity:.75;margin-top:10px">${escapeHtml(footer)}</div>` : ''}
            ${url ? `<div style="font-size:11px;opacity:.75;margin-top:4px">${escapeHtml(url)}</div>` : ''}
        </div>
    `;
}


async function doEmbed() {
    const color = $('#embed-color').value.trim();
    if (color && !validateEmbedColor(color)) return;

    const val = id => ($('#' + id)?.value || '').trim() || undefined;

    const fields = collectEmbedFields();

    const embed = {
        channelId: $('#embed-channel').value,
        title: val('embed-title'),
        description: val('embed-desc'),
        color: color || undefined,
        image: val('embed-image'),
        thumbnail: val('embed-thumb'),
        footer: val('embed-footer'),
        url: val('embed-url'),
        authorName: val('embed-author'),
        authorIcon: val('embed-author-icon'),
        ...(fields.length ? { fields } : {})
    };

    if (!embed.description) return toast('اكتب وصف الإيمبد', 'err');

    try {
        const data = await api(`/api/server/${currentGuildId}/action`, {
            method: 'POST',
            body: JSON.stringify({ action: 'embed', embed })
        });
        toast(data.message || '✅ تم الإرسال');
    } catch (e) { toast(e.message, 'err'); }
}

/* ---------- PROTECTION ---------- */

// المقاييس المتاحة لكل نوع حماية (نفس تعريف index.js)
const PROTECTION_METRICS = {
    channels: [
        { key: 'create', label: 'إنشاء الرومات' },
        { key: 'delete', label: 'حذف الرومات' },
        { key: 'update', label: 'تعديل الرومات' }
    ],
    roles: [
        { key: 'create', label: 'إنشاء الرتب' },
        { key: 'delete', label: 'حذف الرتب' },
        { key: 'update', label: 'تعديل الرتب' }
    ],
    bans: [
        { key: 'count', label: 'عمليات الحظر' }
    ],
    bots: [
        { key: 'joins', label: 'دخول البوتات' }
    ],
    spam: [
        { key: 'messages', label: 'عدد الرسائل' },
        { key: 'length', label: 'أقصى طول رسالة' },
        { key: 'repeat', label: 'تكرار الحرف فقط' },
        { key: 'fontsize', label: 'تكبير الخط فقط' }
    ],
    webhooks: [
        { key: 'create', label: 'إنشاء الويب هوك' },
        { key: 'delete', label: 'حذف/تعديل الويب هوك' }
    ],
    invites: [
        { key: 'redirect', label: 'إعادة توجيه اختصار السيرفر' }
    ],
    scams: [
        { key: 'talk', label: 'عدد الرسائل المسموحة' },
        { key: 'image', label: 'عدد الصور المسموحة' },
        { key: 'links', label: 'عدد الروابط المسموحة' }
    ]
};

const PROTECTION_LABELS = {
    channels: 'الرومات',
    roles: 'الرتب',
    bans: 'حظر الأعضاء',
    bots: 'دخول البوتات',
    spam: 'السبام (تكرار الحرف + تكبير الخط)',
    webhooks: 'الويب هوك',
    invites: 'حماية اختصار السيرفر',
    scams: 'حماية النصب'
};

// ======================================================
// 🔗 حماية الاختصار: اختيار اختصار السيرفر أو تعيينه تلقائياً
// ======================================================

const INVITE_STATE = { loaded: false, invites: [] };

function inviteChannelName(channelId) {
    if (!channelId) return '—';
    return GUILD.channels.find(c => c.id === channelId)
        ? channelName(0, GUILD.channels.find(c => c.id === channelId).name)
        : `روم محذوف`;
}

// بلوك إعدادات اختصار السيرفر: الكود المحمي + قائمة الاختصارات (ممنوع التجاوز دايم)
// ======================================================
// 🚨 حماية النصب: اختيار الروم + القواعد (كلام / صورة / رابط)
// ======================================================

const SCAM_RULE_ROWS = [
    { key: 'onTalk', metric: 'talk', label: '💬 أي كلام', hint: 'ينتبند أي واحد يتكلم بالـ روم' },
    { key: 'onImage', metric: 'image', label: '🖼️ صورة', hint: 'ينتبند أي واحد يرسل صورة أو ملف مرئي' },
    { key: 'onLink', metric: 'links', label: '🔗 رابط', hint: 'ينتبند أي واحد يرسل رابط' }
];

function scamProtectionBlockHTML(conf) {
    const selected = Array.isArray(conf.channelIds) ? conf.channelIds.map(String) : [];
    const textChannels = GUILD.channels.filter(c => c.type === 0);

    const rooms = textChannels.length
        ? textChannels.map(c => `
            <label class="scam-room">
                <input type="checkbox" data-scam-channel="${c.id}" ${selected.includes(c.id) ? 'checked' : ''}>
                <span>#${escapeHtml(c.name)}</span>
            </label>`).join('')
        : '<div style="color:var(--yellow);font-size:12px">ما فيه رومات نصية بالسيرفر.</div>';

    return `
        <div class="scam-block">
            <div class="scam-block-title">🚨 الرومات المحمية <small>اختر روم واحد أو أكثر — اللي يتكلم/يصور/ينرابط داخله ينتبند على طول</small></div>
            <div class="scam-rooms" data-scam-rooms>${rooms}</div>

            <div class="scam-block-title" style="margin-top:12px">📋 القواعد <small>فعّل اللي تبيه — كل قاعدة لها حدها وعقوبتها تحت</small></div>
            <div class="scam-rules">
                ${SCAM_RULE_ROWS.map(r => `
                    <label class="scam-rule ${conf[r.key] ? 'on' : ''}" data-scam-rule-row="${r.key}">
                        <input type="checkbox" data-scam-rule="${r.key}" ${conf[r.key] ? 'checked' : ''}>
                        <div>
                            <b>${r.label}</b>
                            <small>${r.hint}</small>
                        </div>
                    </label>`).join('')}
            </div>

            <div class="section-note" style="margin-top:10px">
                ⛔ العقوبة فورية (الحد الافتراضي 1) — زوّد الحد من فوق لو تبي سماح بسيط.
                <br>الاستثناءات: راعي البوت + البوتات + رتبة الستريتر.
            </div>
        </div>`;
}

// يقرأ رومات حماية النصب + قواعدها من الكارت
function collectScamConfig() {
    const channelIds = [...document.querySelectorAll('[data-scam-channel]')]
        .filter(box => box.checked)
        .map(box => box.dataset.scamChannel);

    const out = { channelIds };
    for (const rule of ['onTalk', 'onImage', 'onLink']) {
        out[rule] = !!document.querySelector(`[data-scam-rule="${rule}"]`)?.checked;
    }
    return out;
}

function inviteProtectionBlockHTML(conf) {
    const code = conf.code || '';

    return `
        <div class="invite-block">
            <div class="invite-current">
                <div>
                    <b>الاختصار المحمي الآن</b>
                    <small>
                        ${code
                            ? `<a href="https://discord.gg/${escapeHtml(code)}" target="_blank" rel="noopener">discord.gg/${escapeHtml(code)}</a> — ${escapeHtml(inviteChannelName(conf.channelId))}`
                            : '<span style="color:var(--yellow)">غير معيّن — اضغط «تعيين تلقائي» أو اختر اختصار من سيرفرك</span>'}
                    </small>
                </div>
                <div style="display:flex;gap:6px;flex-wrap:wrap">
                    <button type="button" class="btn btn-ghost btn-sm" data-action="invite-load">🔄 جيب اختصارات سيرفرك</button>
                    <button type="button" class="btn btn-primary btn-sm" data-action="invite-auto">⚡ تعيين تلقائي</button>
                </div>
            </div>

            <div id="invite-picker" class="invite-picker">
                <div style="color:var(--muted);font-size:12px">اضغط «جيب اختصارات سيرفرك» حتى تظهر لك اختصاراتك وتختار منها.</div>
            </div>

            <div class="invite-create">
                <select id="invite-create-channel">
                    <option value="">— أنشئ اختصار جديد من روم —</option>
                    ${GUILD.channels.filter(c => c.type === 0).map(c =>
                        `<option value="${c.id}">${channelName(0, c.name)}</option>`
                    ).join('')}
                </select>
                <button type="button" class="btn btn-ghost btn-sm" data-action="invite-create">➕ إنشاء وحماية</button>
            </div>

            <div class="section-note" style="margin-top:10px">
                ⛔ <b>ممنوع التجاوز</b>: الحد صفر — أول ما ينشال الاختصار ينزل العقوبة فوراً على اللي شالله
                بدون انتظار. ما أحد يتجاوز (ولا الوايت ليست ولا رتبة المشرف) — الاستثناء الوحيد راعي البوت.<br>
                العقوبة: تختار ⚡ اختصار من اختصاراتك (تبويب ⚡ الاختصارات) فينفذ على طول على اللي شال الاختصار.
            </div>
        </div>`;
}

function renderInvitePicker() {
    const box = $('#invite-picker');
    if (!box) return;

    if (!INVITE_STATE.loaded) {
        box.innerHTML = `<div style="color:var(--muted);font-size:12px">اضغط «جيب اختصارات سيرفرك» حتى تظهر لك اختصاراتك وتختار منها.</div>`;
        return;
    }

    const list = INVITE_STATE.invites;
    const current = (GUILD.settings.protections?.invites || {}).code || '';

    if (!list.length) {
        box.innerHTML = `<div style="color:var(--yellow);font-size:12px">ما فيه أي اختصار بالسيرفر. أنشئ واحد من الروم تحت 👇</div>`;
        return;
    }

    box.innerHTML = `
        <div class="invite-list">
            ${list.map(i => `
                <button type="button" class="invite-chip ${i.code === current ? 'active' : ''}" data-action="invite-assign" data-code="${escapeHtml(i.code)}">
                    <b>discord.gg/${escapeHtml(i.code)}</b>
                    <small>${escapeHtml(channelName(0, i.channelName))} • 👥 ${i.uses} استخدام${i.protected ? ' • 🛡️ محمي' : ''}</small>
                </button>
            `).join('')}
        </div>`;
}

async function loadServerInvites() {
    try {
        const data = await api(`/api/server/${currentGuildId}/invites`);
        INVITE_STATE.loaded = true;
        INVITE_STATE.invites = data.invites || [];
        renderInvitePicker();
        toast(`✅ جبت ${INVITE_STATE.invites.length} اختصار من سيرفرك`);
    } catch (e) { toast(e.message, 'err'); }
}

async function assignInvite(mode, extra = {}) {
    try {
        const res = await api(`/api/server/${currentGuildId}/invites`, {
            method: 'POST',
            body: JSON.stringify({ mode, ...extra })
        });

        GUILD.settings = res.settings;
        if (mode !== 'off') INVITE_STATE.invites = INVITE_STATE.invites.map(i => ({
            ...i,
            protected: i.code === res.code,
            code: i.code
        }));

        renderProtection();
        toast(res.message || '✅ تم');
    } catch (e) { toast(e.message, 'err'); }
}

const ACTION_OPTIONS = [
    { value: 'shortcut', label: '⚡ اختيار اختصارك' },
    { value: 'ban', label: '🔨 Ban' },
    { value: 'kick', label: '👢 Kick' },
    { value: 'timeout', label: '🔇 Time-out' },
    { value: 'jail', label: '🔒 سجن (ما يشوف ولا روم)' },
    { value: 'removeroles', label: '🎭 إزالة الرتب' }
];

// أوامر الاختصارات اللي تقدر تكون عقوبة (نفس قيم SHORTCUT_COMMANDS)
const SHORTCUT_PUNISH_COMMANDS = ['ban', 'kick', 'timeout', 'jail'];


// اختصارات المستخدم الصالحة كعقوبة حماية
function punishShortcuts() {
    return (GUILD?.settings?.shortcuts || [])
        .filter(s => SHORTCUT_PUNISH_COMMANDS.includes(s.command))
        .map(s => ({ name: s.name, command: s.command }));
}

// حدود جاهزة تختارها بضغطة (تقدر تكتب رقمك الخاص من "مخصص")
const LIMIT_PRESETS = [3, 4, 5, 6, 7, 8, 10, 15, 20, 25, 30, 50, 75, 100, 150, 200, 500, 1000];
const CUSTOM_LIMIT = 'custom';

function protectionMetrics(typeKey) {
    return PROTECTION_METRICS[typeKey] || [];
}

function metricValue(prot, metricKey, fallback) {
    const stored = Number(prot?.metrics?.[metricKey]);
    if (Number.isFinite(stored) && stored > 0) return stored;
    return fallback;
}

function metricActionValue(prot, metricKey) {
    return prot?.metricActions?.[metricKey] || prot?.action || 'ban';
}

// صف واحد: اسم المقياس + قائمة اختيار الحد (جاهز/مخصص) + قائمة العقوبة
function metricRowHTML(typeKey, metricKey, metricLabel, prot) {
    const value = metricValue(prot, metricKey, 5);
    const action = metricActionValue(prot, metricKey);
    const isPreset = LIMIT_PRESETS.includes(value);
    const selectValue = isPreset ? String(value) : CUSTOM_LIMIT;

    const presets = LIMIT_PRESETS
        .map(n => `<option value="${n}" ${n === value ? 'selected' : ''}>${n}</option>`)
        .join('');

    // ⚡ الاختصار المختار لهذه العقوبة (المخزّن بصيغة shortcut:<name>)
    const pickedShortcut = String(action).startsWith('shortcut:') ? action.slice(9).trim() : '';
    const myShortcuts = punishShortcuts();

    const actionSelect = `
        <select data-metric-select="${typeKey}:${metricKey}">
            ${ACTION_OPTIONS.map(a => {
                const selected = a.value === 'shortcut'
                    ? String(action).startsWith('shortcut:')
                    : a.value === action;
                return `<option value="${a.value}" ${selected ? 'selected' : ''}>${a.label}</option>`;
            }).join('')}
        </select>`;

    // قائمة اختيار الاختصار (تظهر بس لما يختار "اختيار اختصارك")
    const shortcutSelect = String(action).startsWith('shortcut:') ? `
        <select data-metric-shortcut="${typeKey}:${metricKey}" class="metric-shortcut">
            ${myShortcuts.length === 0
                ? '<option value="">ما فيه اختصارات — أضفها من تبويب ⚡ الاختصارات</option>'
                : myShortcuts.map(s => `
                    <option value="${escapeHtml(s.name)}" ${normalizeText(s.name) === normalizeText(pickedShortcut) ? 'selected' : ''}>
                        ⚡ ${escapeHtml(s.name)} — ${escapeHtml(s.command)}
                    </option>
                `).join('')}
        </select>` : '';

    return `
        <div class="switch-row metric-row" data-metric-row="${typeKey}:${metricKey}">
            <div class="txt">
                <b>${escapeHtml(metricLabel)}</b>
                <small>${typeKey === 'invites'
                    ? `العقوبة: <span data-metric-action-current="${metricKey}">${escapeHtml(actionLabel(action))}</span> — تُطبّق فوراً عند أول حذف`
                    : `الحد الحالي: <span data-metric-current="${metricKey}">${value}</span> — العقوبة: <span data-metric-action-current="${metricKey}">${escapeHtml(actionLabel(action))}</span>`}</small>
            </div>
            <div class="metric-controls">
                ${typeKey === 'invites' ? '' : `
                <select data-metric-preset="${typeKey}:${metricKey}">
                    ${presets}
                    <option value="${CUSTOM_LIMIT}" ${selectValue === CUSTOM_LIMIT ? 'selected' : ''}>✏️ مخصص</option>
                </select>
                <input
                    type="number"
                    min="1"
                    max="100000"
                    step="1"
                    value="${value}"
                    data-metric-input="${typeKey}:${metricKey}"
                    class="metric-custom ${selectValue === CUSTOM_LIMIT ? '' : 'hidden'}"
                >`}
                ${actionSelect}
                ${shortcutSelect}
            </div>
        </div>`;
}

function actionLabel(value) {
    if (String(value).startsWith('shortcut:')) {
        const name = String(value).slice(9).trim();
        return `⚡ ${name || 'اختصارك'}`;
    }
    return ACTION_OPTIONS.find(a => a.value === value)?.label || '🔨 Ban';
}
// كارت حماية واحدة: بالضغط عليه تنزل قائمة الحدود
function protectionCardHTML(typeKey, conf) {
    const metrics = protectionMetrics(typeKey);
    const enabledCount = metrics.filter(m => metricValue(conf, m.key, 0) > 0).length;

    return `
        <div class="panel-card prot-card" data-prot-card="${typeKey}">
            <button type="button" class="prot-head" data-action="toggle-prot-card" data-key="${typeKey}" aria-expanded="false">
                <div class="txt">
                    <b>🛡️ ${escapeHtml(PROTECTION_LABELS[typeKey] || typeKey)}</b>
                    <small>${metrics.length ? `${metrics.length} عمليات — اضغط عشان تضبط الحدود` : 'بدون مقاييس'}</small>
                </div>
                <span class="prot-state ${conf.enabled ? 'on' : 'off'}">${conf.enabled ? 'مفعّلة' : 'معطّلة'}</span>
                <span class="sc-arrow">▾</span>
            </button>

            <div class="prot-body">
                <div class="switch-row" style="border-bottom:none;padding-top:0">
                    <div class="txt">
                        <b>تفعيل ${escapeHtml(PROTECTION_LABELS[typeKey] || typeKey)}</b>
                        <small>${enabledCount ? `الحدود مضبوطة لـ ${enabledCount} عملية` : 'اختر الحد لكل عملية'}</small>
                    </div>
                    <label class="toggle">
                        <input type="checkbox" ${conf.enabled ? 'checked' : ''} data-protection-key="${typeKey}">
                        <span class="slider"></span>
                    </label>
                </div>
                ${metrics.length ? metrics.map(m => metricRowHTML(typeKey, m.key, m.label, conf)).join('') : ''}
                ${typeKey === 'invites' ? inviteProtectionBlockHTML(conf) : ''}
                ${typeKey === 'scams' ? scamProtectionBlockHTML(conf) : ''}
            </div>
        </div>`;
}

function renderProtection() {
    const prot = GUILD.settings.protections || {};

    panelHTML(`
        <div class="panel-card" style="border-color:var(--red-dark)">
            <h3>🛡️ الحماية</h3>
            <div class="section-note">
                اضغط على أي حماية من القائمة فتنزل لك حدودها،اختر الحد الجاهز أو اكتب رقمك بنفسك من "مخصص"، وحدد العقوبة.
                العقوبة: 🔨 Ban / 👢 Kick / 🔇 Time-out / 🎭 إزالة الرتب.
            </div>
        </div>

        <div class="prot-list">
            ${Object.keys(PROTECTION_METRICS).map(key => protectionCardHTML(key, prot[key] || {})).join('')}
        </div>

        <div class="panel-card">
            <h3>💾 حفظ</h3>
            <div class="section-note">اضغط على الحمايات اللي تبي تعدّلها، عدّل الأرقام ثم اضغط حفظ.</div>
            <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
                <button type="button" class="btn btn-primary" data-action="save-protection">💾 حفظ كل الحماية</button>
                <button type="button" class="btn btn-ghost" data-action="open-all-protections">📂 فتح الكل</button>
                <button type="button" class="btn btn-ghost" data-action="close-all-protections">📁 إغلاق الكل</button>
            </div>
            <div id="p-result"></div>
        </div>
    `);

    bindProtectionRows();
}

function bindProtectionRows() {
    // 🔗 حماية الاختصار: عرض قائمة اختصارات السيرفر أول ما تفتح الكارت
    renderInvitePicker();

    for (const preset of document.querySelectorAll('[data-metric-preset]')) {
        preset.onchange = () => {
            const key = preset.dataset.metricPreset;
            const row = document.querySelector(`[data-metric-row="${key}"]`);
            if (!row) return;

            const [typeKey, metricKey] = key.split(':');
            const custom = row.querySelector(`[data-metric-input="${typeKey}:${metricKey}"]`);
            const current = row.querySelector(`[data-metric-current="${metricKey}"]`);

            if (preset.value === CUSTOM_LIMIT) {
                custom?.classList.remove('hidden');
                custom?.focus();
                custom?.select?.();
            } else {
                custom?.classList.add('hidden');
                if (custom) custom.value = preset.value;
                if (current) current.textContent = preset.value;
            }
        };
    }

    for (const custom of document.querySelectorAll('[data-metric-input]')) {
        custom.oninput = () => {
            const key = custom.dataset.metricInput;
            const [typeKey, metricKey] = key.split(':');
            const row = document.querySelector(`[data-metric-row="${typeKey}:${metricKey}"]`);
            const current = row?.querySelector(`[data-metric-current="${metricKey}"]`);
            const value = Math.max(1, Math.min(100000, Math.round(Number(custom.value) || 1)));
            if (current) current.textContent = value;
        };
    }

    // ⚡ قائمة العقوبة: لمّا يختار "اختيار اختصارك" تظهر قائمة الاختصارات
    for (const select of document.querySelectorAll('[data-metric-select]')) {
        select.onchange = () => {
            const key = select.dataset.metricSelect;
            const [typeKey, metricKey] = key.split(':');
            const row = document.querySelector(`[data-metric-row="${typeKey}:${metricKey}"]`);
            if (!row) return;

            const actionCurrent = row.querySelector(`[data-metric-action-current="${metricKey}"]`);
            const existing = row.querySelector(`[data-metric-shortcut="${typeKey}:${metricKey}"]`);

            if (select.value !== 'shortcut') {
                existing?.remove();
                if (actionCurrent) actionCurrent.textContent = actionLabel(select.value);
                return;
            }

            if (existing) {
                if (actionCurrent) actionCurrent.textContent = actionLabel(`shortcut:${existing.value}`);
                return;
            }

            // ما فيه اختصارات محفوظة → نرجع للعقوبة الافتراضية وننبّه
            const list = punishShortcuts();
            if (list.length === 0) {
                select.value = 'ban';
                toast('أضف اختصار من تبويب ⚡ الاختصارات أول قبل ما تختاره كعقوبة', 'err');
                if (actionCurrent) actionCurrent.textContent = actionLabel('ban');
                return;
            }

            const picker = document.createElement('select');
            picker.className = 'metric-shortcut';
            picker.dataset.metricShortcut = key;
            picker.innerHTML = list.map(s => `
                <option value="${escapeHtml(s.name)}">⚡ ${escapeHtml(s.name)} — ${escapeHtml(s.command)}</option>
            `).join('');

            select.after(picker);
            if (actionCurrent) actionCurrent.textContent = actionLabel(`shortcut:${picker.value}`);
        };
    }

    // ⚡ قائمة الاختصار نفسها: تحدّث النص المعروض
    for (const picker of document.querySelectorAll('[data-metric-shortcut]')) {
        picker.onchange = () => {
            const key = picker.dataset.metricShortcut;
            const [, metricKey] = key.split(':');
            const row = document.querySelector(`[data-metric-row="${key}"]`);
            const actionCurrent = row?.querySelector(`[data-metric-action-current="${metricKey}"]`);
            if (actionCurrent) actionCurrent.textContent = actionLabel(`shortcut:${picker.value}`);
        };
    }
}

function setProtectionCard(key, open) {
    const card = document.querySelector(`[data-prot-card="${key}"]`);
    if (!card) return;
    card.classList.toggle('open', open);
    card.querySelector('.prot-head')?.setAttribute('aria-expanded', String(open));
}

function toggleProtectionCard(key) {
    const card = document.querySelector(`[data-prot-card="${key}"]`);
    if (!card) return;
    setProtectionCard(key, !card.classList.contains('open'));
}

async function protToggle(key, enabled) {
    try {
        const data = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'protections', data: { [key]: { enabled } } })
        });
        GUILD.settings = data.settings;
        toast(`✅ تم ${enabled ? 'تفعيل' : 'إيقاف'} الحماية (${PROTECTION_LABELS[key] || key})`);
    } catch (e) { toast(e.message, 'err'); }
}

// يجمع كل الصفوف → { typeKey: { metrics: {...}, metricActions: {...} } }
function collectProtectionData() {
    const payload = {};

    for (const row of document.querySelectorAll('.metric-row')) {
        const [typeKey, metricKey] = row.dataset.metricRow.split(':');
        const preset = row.querySelector(`[data-metric-preset="${typeKey}:${metricKey}"]`);
        const input = row.querySelector(`[data-metric-input="${typeKey}:${metricKey}"]`);
        const select = row.querySelector(`[data-metric-select="${typeKey}:${metricKey}"]`);

        // الحد إما من القائمة الجاهزة أو من الحقل اليدوي ("مخصص")
        const raw = preset && preset.value !== CUSTOM_LIMIT ? preset.value : (input?.value ?? '');
        const limit = Math.max(1, Math.min(100000, Math.round(Number(raw) || 1)));

        if (!payload[typeKey]) payload[typeKey] = { metrics: {}, metricActions: {} };
        payload[typeKey].metrics[metricKey] = limit;

        // العقوبة: قاعدة جاهزة أو ⚡ اختصار بصيغة shortcut:<name>
        const shortcutSelect = row.querySelector(`[data-metric-shortcut="${typeKey}:${metricKey}"]`);
        if (select.value === 'shortcut') {
            const name = String(shortcutSelect?.value || '').trim();
            payload[typeKey].metricActions[metricKey] = name ? `shortcut:${name}` : '';
        } else {
            payload[typeKey].metricActions[metricKey] = select.value;
        }

        // مزامنة القائمة الجاهزة مع الرقم اليدوي حتى لا يختلفا
        if (preset && preset.value === CUSTOM_LIMIT) {
            if (LIMIT_PRESETS.includes(limit)) preset.value = String(limit);
            if (input) input.value = limit;
        }

        // تحديث المعروض في السطر بدون إعادة رسم كامل
        const current = row.querySelector(`[data-metric-current="${metricKey}"]`);
        const actionCurrent = row.querySelector(`[data-metric-action-current="${metricKey}"]`);
        const rowShortcut = row.querySelector(`[data-metric-shortcut="${typeKey}:${metricKey}"]`);
        if (current) current.textContent = limit;
        if (actionCurrent) {
            actionCurrent.textContent = select.value === 'shortcut'
                ? actionLabel(`shortcut:${String(rowShortcut?.value || '').trim()}`)
                : actionLabel(select.value);
        }
    }

    // حالة التفعيلات
    for (const box of document.querySelectorAll('[data-protection-key]')) {
        const key = box.dataset.protectionKey;
        if (!payload[key]) payload[key] = { metrics: {}, metricActions: {} };
        payload[key].enabled = box.checked;

        const state = document.querySelector(`[data-prot-card="${key}"] .prot-state`);
        if (state) {
            state.textContent = box.checked ? 'مفعّلة' : 'معطّلة';
            state.classList.toggle('on', box.checked);
            state.classList.toggle('off', !box.checked);
        }
    }

    // 🚨 حماية النصب: الروم المختار + القواعد
    if (document.querySelector('[data-scam-rooms]')) {
        if (!payload.scams) payload.scams = { metrics: {}, metricActions: {} };
        Object.assign(payload.scams, collectScamConfig());
    }

    return payload;
}

async function updateProtection() {
    const data = collectProtectionData();

    // تحقّق قبل الإرسال: حماية النصب لازم روم + قاعدة واحدة على الأقل
    if (data.scams?.enabled === true) {
        if (!data.scams.channelIds?.length) {
            const msg = '🚨 حماية النصب: اختر روم محمي واحد على الأقل.';
            $('#p-result').innerHTML = `<div class="result-box err">${escapeHtml(msg)}</div>`;
            return toast(msg, 'err');
        }
        if (!(data.scams.onTalk || data.scams.onImage || data.scams.onLink)) {
            const msg = '🚨 حماية النصب: فعّل قاعدة واحدة على الأقل (كلام / صورة / رابط).';
            $('#p-result').innerHTML = `<div class="result-box err">${escapeHtml(msg)}</div>`;
            return toast(msg, 'err');
        }
    }

    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'protections', data })
        });
        GUILD.settings = res.settings;
        $('#p-result').innerHTML = '<div class="result-box ok">✅ تم حفظ كل الحدود والعقوبات</div>';
        toast('✅ تم تحديث إعدادات الحماية');
    } catch (e) {
        $('#p-result').innerHTML = `<div class="result-box err">${escapeHtml(e.message)}</div>`;
    }
}

/* ---------- WELCOME ---------- */

function renderWelcome() {
    const w = GUILD.settings.welcome || {};

    panelHTML(`
        <div class="panel-card">
            <h3>👋 نظام الترحيب</h3>
            <div class="switch-row">
                <div class="txt">
                    <b>تفعيل الترحيب</b>
                    <small>إرسال ترحيب عند دخول عضو جديد</small>
                </div>
                <label class="toggle">
                    <input type="checkbox" id="w-enabled" ${w.enabled ? 'checked' : ''}>
                    <span class="slider"></span>
                </label>
            </div>
        </div>

        <div class="panel-card">
            <h3>⚙️ الإعدادات</h3>
            <div class="form-field" style="margin-bottom:12px">
                <label>روم الترحيب</label>
                <select id="w-channel">
                    <option value="">— اختر الروم —</option>
                    ${GUILD.channels.filter(c => c.type === 0).map(c =>
                        `<option value="${c.id}" ${String(w.channelId) === String(c.id) ? 'selected' : ''}>${channelName(0, c.name)}</option>`
                    ).join('')}
                </select>
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>رسالة الترحيب (المتغيرات: {user} {username} {tag} {count} {server} {id})</label>
                <textarea id="w-message">${escapeHtml(w.message || '')}</textarea>
            </div>
            <div class="switch-row">
                <div class="txt">
                    <b>صورة الترحيب (Card)</b>
                    <small>بطاقة Canvas جميلة مع الرسالة</small>
                </div>
                <label class="toggle">
                    <input type="checkbox" id="w-card" ${w.cardEnabled !== false ? 'checked' : ''}>
                    <span class="slider"></span>
                </label>
            </div>
            <div class="form-field" style="margin-top:12px">
                <label>صورة ترحيبية خاصة بك (اختياري — إن وُضعت تحل محل البطاقة)</label>
                <input id="w-image" placeholder="https://i.imgur.com/....png" value="${escapeHtml(w.image || '')}">
            </div>
            <div style="margin-top:14px">
                <button type="button" class="btn btn-primary" data-action="save-welcome">💾 حفظ</button>
            </div>
            <div id="w-result"></div>
        </div>
    `);
}

async function saveWelcome() {
    const data = {
        enabled: $('#w-enabled').checked,
        channelId: $('#w-channel').value || null,
        message: $('#w-message').value,
        cardEnabled: $('#w-card').checked,
        image: $('#w-image').value.trim() || null
    };
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'welcome', data })
        });
        GUILD.settings = res.settings;
        $('#w-result').innerHTML = '<div class="result-box ok">✅ تم الحفظ</div>';
        toast('✅ تم حفظ إعدادات الترحيب');
    } catch (e) {
        $('#w-result').innerHTML = `<div class="result-box err">${escapeHtml(e.message)}</div>`;
    }
}

/* ---------- TICKETS ---------- */

function renderTickets() {
    const t = GUILD.settings.tickets || {};

    panelHTML(`
        <div class="panel-card">
            <h3>🎫 نظام التكتات</h3>
            <div class="switch-row">
                <div class="txt">
                    <b>تفعيل التكتات</b>
                    <small>يسمح للأعضاء بفتح تكتات عبر لوحة</small>
                </div>
                <label class="toggle">
                    <input type="checkbox" id="t-enabled" ${t.enabled ? 'checked' : ''}>
                    <span class="slider"></span>
                </label>
            </div>
        </div>

        <div class="panel-card">
            <h3>⚙️ الإعدادات</h3>
            <div class="form-field" style="margin-bottom:12px">
                <label>روم لوحة التكتات (يظهر فيه زر فتح تكت)</label>
                <select id="t-panel">
                    <option value="">— اختر —</option>
                    ${GUILD.channels.filter(c => c.type === 0).map(c =>
                        `<option value="${c.id}" ${String(t.panelChannelId) === String(c.id) ? 'selected' : ''}>${channelName(0, c.name)}</option>`
                    ).join('')}
                </select>
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>الكاتقري (تفتح فيه التكتات)</label>
                <select id="t-category">
                    <option value="">— بدون كاتقري —</option>
                    ${GUILD.channels.filter(c => c.type === 4).map(c =>
                        `<option value="${c.id}" ${String(t.categoryId) === String(c.id) ? 'selected' : ''}>${channelName(4, c.name)}</option>`
                    ).join('')}
                </select>
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>رتبة الدعم (التي تشوف وتستلم التكتات)</label>
                <select id="t-role">
                    <option value="">— اختر رتبة —</option>
                    ${GUILD.roles.map(r =>
                        `<option value="${r.id}" ${String(t.supportRoleId) === String(r.id) ? 'selected' : ''}>${escapeHtml(r.name)}</option>`
                    ).join('')}
                </select>
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>روم السجل (اختياري)</label>
                <select id="t-log">
                    <option value="">— بدون —</option>
                    ${GUILD.channels.filter(c => c.type === 0).map(c =>
                        `<option value="${c.id}" ${String(t.logChannelId) === String(c.id) ? 'selected' : ''}>${channelName(0, c.name)}</option>`
                    ).join('')}
                </select>
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>رسالة لوحة التكتات / الترحيب داخل التكت</label>
                <textarea id="t-message">${escapeHtml(t.welcomeMessage || '')}</textarea>
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>صورة لوحة التكتات (اختياري)</label>
                <input id="t-panel-image" placeholder="https://....png" value="${escapeHtml(t.panelImage || '')}">
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>صورة الترحيب داخل التكت (اختياري)</label>
                <input id="t-welcome-image" placeholder="https://....png" value="${escapeHtml(t.welcomeImage || '')}">
            </div>
            <div class="form-field" style="margin-bottom:12px">
                <label>أقصى عدد تكتات للعضو الواحد</label>
                <input type="number" id="t-max" min="1" max="20" value="${Number(t.maxPerUser) || 1}">
            </div>
            <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap">
                <button type="button" class="btn btn-primary" data-action="save-tickets">💾 حفظ</button>
                ${t.enabled && t.panelChannelId ? `<button type="button" class="btn btn-ghost" data-action="send-ticket-panel">📤 إرسال اللوحة الآن</button>` : ''}
            </div>
            <div id="t-result"></div>
        </div>

        <div class="panel-card">
            <h3>🗂️ خيارات التكت (أنواعه)</h3>
            <div class="section-note">
                كل خيار = زر في اللوحة. مثال: «دعم فني» و«شكوى» و«استفسار» — كل واحد زر لحاله بzezوره ووصفه.
                الترتيب يحدد ترتيب الأزرار في اللوحة.
                <br>الحالة: <b>✅ مفعّل</b> (يفتح تكت) أو <b>⏸️ معلق</b> (الزر يبان بس معطّل وما يفتح تكت) — تغيّرها من قائمة الحالة اللي عند كل خيار.
            </div>

            <div id="t-options-list" style="margin-top:12px">
                ${ticketOptionsListHTML(t.options)}
            </div>

            <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
                <button type="button" class="btn btn-ghost btn-sm" data-action="ticket-option-add">➕ إضافة خيار</button>
            </div>

            <div class="form-field" style="margin-top:16px">
                <label>رسالة معاينة الأزرار</label>
                <div id="t-options-preview"></div>
            </div>

            <div style="margin-top:14px">
                <button type="button" class="btn btn-primary" data-action="save-tickets">💾 حفظ الخيارات</button>
            </div>
        </div>
    `);

    bindTicketOptions();
}

const TICKET_EMOJI_CHOICES = ['🎫', '🛠️', '📢', '⚠️', '❓', '💰', '🧩', '📦', '🔧', '⭐'];

function ticketOptionsListHTML(options) {
    const list = Array.isArray(options) ? options : [];

    if (!list.length) {
        return `<div style="color:var(--muted);font-size:13px">لا توجد خيارات — سيظهر زر واحد فقط في اللوحة.</div>`;
    }

    return list.map((o, i) => `
        <div class="switch-row ticket-option-row ${o.suspended ? 'opt-suspended' : ''}" data-option-index="${i}" style="align-items:flex-start;flex-direction:column;gap:8px">
            <div class="form-grid" style="grid-template-columns:70px 1fr 1fr;gap:8px;width:100%">
                <div class="form-field">
                    <label>الإيموجي</label>
                    <input data-opt="emoji" value="${escapeHtml(o.emoji || '🎫')}" maxlength="4">
                </div>
                <div class="form-field">
                    <label>اسم الزر</label>
                    <input data-opt="label" value="${escapeHtml(o.label || '')}" placeholder="دعم فني">
                </div>
                <div class="form-field">
                    <label>الوصف (اختياري)</label>
                    <input data-opt="description" value="${escapeHtml(o.description || '')}" placeholder="للاستفسارات التقنية">
                </div>
            </div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                <select data-opt="suspended" class="opt-state" title="حالة الخيار">
                    <option value="0" ${o.suspended ? '' : 'selected'}>✅ مفعّل</option>
                    <option value="1" ${o.suspended ? 'selected' : ''}>⏸️ معلق</option>
                </select>
                <label class="check-inline"><input type="checkbox" data-opt="staffOnly" ${o.staffOnly ? 'checked' : ''}> للفريق فقط</label>
                <button type="button" class="btn btn-ghost btn-sm" data-action="ticket-option-up" data-index="${i}" ${i === 0 ? 'disabled' : ''}>▲</button>
                <button type="button" class="btn btn-ghost btn-sm" data-action="ticket-option-down" data-index="${i}" ${i === list.length - 1 ? 'disabled' : ''}>▼</button>
                <button type="button" class="btn btn-danger btn-sm" data-action="ticket-option-remove" data-index="${i}">🗑️ حذف</button>
            </div>
        </div>
    `).join('');
}

// يقرأ الخيارات من الكارت الحالي
// includeEmpty = true: نخلي الصفوف الفاضية (أثناء الإضافة) عشان ما تختفي
function collectTicketOptions(includeEmpty = false) {
    const rows = [...document.querySelectorAll('.ticket-option-row')];

    const options = rows.map((row, i) => {
        const label = row.querySelector('[data-opt="label"]').value.trim();
        const key = `opt${i + 1}`;

        return {
            key,
            label: label.slice(0, 80),
            description: row.querySelector('[data-opt="description"]').value.trim().slice(0, 100),
            emoji: (row.querySelector('[data-opt="emoji"]').value.trim() || '🎫').slice(0, 4),
            staffOnly: row.querySelector('[data-opt="staffOnly"]').checked,
            suspended: row.querySelector('[data-opt="suspended"]')?.value === '1'
        };
    });

    return includeEmpty ? options : options.filter(o => o.label);
}

function renderTicketOptionsPreview() {
    const el = $('#t-options-preview');
    if (!el) return;

    const options = collectTicketOptions();

    if (!options.length) {
        el.innerHTML = `<div style="color:var(--muted);font-size:13px">أضف خياراً واحداً على الأقل لعرض الأزرار.</div>`;
        return;
    }

    el.innerHTML = `<div style="display:flex;flex-wrap:wrap;gap:8px">${options.map(o => {
        const color = o.suspended ? '#8b8b8b' : (o.staffOnly ? '#5865F2' : '#57F287');
        return `
        <span style="background:${color}22;border:1px solid ${color};border-radius:6px;padding:6px 12px;font-size:13px;${o.suspended ? 'opacity:.7;text-decoration:line-through' : ''}">
            ${escapeHtml(o.emoji)} ${escapeHtml(o.label)}${o.suspended ? ' <small style="opacity:.9">(معلّق)</small>' : (o.staffOnly ? ' <small style="opacity:.7">(فريق)</small>' : '')}
        </span>`;
    }).join('')}</div>`;
}

function bindTicketOptions() {
    const list = $('#t-options-list');
    if (!list) return;

    // نربط مرة وحدة فقط (الـ innerHTML يتغير، لكن العنصر نفسه لا)
    if (!list.dataset.bound) {
        list.dataset.bound = '1';
        list.addEventListener('input', renderTicketOptionsPreview);
        list.addEventListener('change', e => {
            // تبديل حالة الخيار (مفعّل ⇄ معلق) بدون ما نعيد رسم كل الكارت
            if (e.target.matches?.('[data-opt="suspended"]')) {
                e.target.closest('.ticket-option-row')?.classList.toggle('opt-suspended', e.target.value === '1');
            }
            renderTicketOptionsPreview();
        });
    }

    renderTicketOptionsPreview();
}

// يرسم صفوف الخيارات من مصفوفة (+ يربط الأحداث)
function renderTicketOptionRows(options) {
    const list = $('#t-options-list');
    if (!list) return;
    list.innerHTML = ticketOptionsListHTML(options);
    bindTicketOptions();
}

function moveTicketOption(index, dir) {
    const options = collectTicketOptions(true);
    const target = index + dir;
    if (target < 0 || target >= options.length) return;

    [options[index], options[target]] = [options[target], options[index]];
    renderTicketOptionRows(options);
}

function addTicketOption() {
    const options = collectTicketOptions(true);
    if (options.length >= 25) return toast('أقصى عدد خيارات 25', 'err');

    options.push({
        key: `opt${options.length + 1}`,
        label: '',
        description: '',
        emoji: TICKET_EMOJI_CHOICES[options.length % TICKET_EMOJI_CHOICES.length],
        staffOnly: false,
        suspended: false
    });
    renderTicketOptionRows(options);

    // نركز على اسم الخيار الجديد
    const rows = document.querySelectorAll('.ticket-option-row');
    rows[rows.length - 1]?.querySelector('[data-opt="label"]')?.focus();
}

function removeTicketOption(index) {
    const options = collectTicketOptions(true);
    if (index < 0 || index >= options.length) return;
    options.splice(index, 1);
    renderTicketOptionRows(options);
}

async function saveTickets() {
    const data = {
        enabled: $('#t-enabled').checked,
        panelChannelId: $('#t-panel').value || null,
        categoryId: $('#t-category').value || null,
        supportRoleId: $('#t-role').value || null,
        logChannelId: $('#t-log').value || null,
        welcomeMessage: $('#t-message').value,
        panelImage: $('#t-panel-image').value.trim() || null,
        welcomeImage: $('#t-welcome-image').value.trim() || null,
        maxPerUser: Number($('#t-max').value) || 1,
        options: collectTicketOptions()
    };
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'tickets', data })
        });
        GUILD.settings = res.settings;
        $('#t-result').innerHTML = '<div class="result-box ok">✅ تم الحفظ</div>';
        renderTickets();
        toast('✅ تم حفظ إعدادات التكتات');
    } catch (e) {
        $('#t-result').innerHTML = `<div class="result-box err">${escapeHtml(e.message)}</div>`;
    }
}

async function sendTicketPanel() {
    try {
        await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'tickets', data: { sendPanel: true } })
        });
        toast('✅ تم إرسال لوحة التكتات');
    } catch (e) { toast(e.message, 'err'); }
}

/* ---------- LOGS ---------- */

function renderLogs() {
    const logs = GUILD.settings.logs || {};

    const labels = {
        moderation: 'سجل الإدارة (باند/كيك/تايم أوت...)',
        member: 'سجل الأعضاء (انضمام/مغادرة)',
        channel: 'سجل الرومات (إنشاء/حذف)',
        role: 'سجل الرتب (إنشاء/تعديل)',
        voice: 'سجل الصوتيات',
        message: 'سجل الرسائل (حذف)',
        webhook: 'سجل الويب هوك',
        protection: 'سجل الحماية (نوك)'
    };

    const rows = Object.keys(labels).map(key => `
        <div class="form-field" style="margin-bottom:10px">
            <label>${labels[key]}</label>
            <select id="log-${key}" data-key="${key}">
                <option value="">— معطل —</option>
                ${GUILD.channels.filter(c => c.type === 0).map(c =>
                    `<option value="${c.id}" ${String(logs[key]) === String(c.id) ? 'selected' : ''}>${channelName(0, c.name)}</option>`
                ).join('')}
            </select>
        </div>
    `).join('');

    panelHTML(`
        <div class="panel-card">
            <h3>📜 سجلات السيرفر</h3>
            <div class="section-note">اختر روم لكل نوع سجل. الحفظ يطبق كل التغييرات دفعة واحدة.</div>
            ${rows}
            <div style="margin-top:14px">
                <button type="button" class="btn btn-primary" data-action="save-logs">💾 حفظ كل السجلات</button>
            </div>
            <div id="log-result"></div>
        </div>
    `);
}

async function saveLogs() {
    const data = {};
    document.querySelectorAll('[id^="log-"]').forEach(el => {
        data[el.dataset.key] = el.value || null;
    });
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'logs', data })
        });
        GUILD.settings = res.settings;
        $('#log-result').innerHTML = '<div class="result-box ok">✅ تم الحفظ</div>';
        toast('✅ تم حفظ السجلات');
    } catch (e) {
        $('#log-result').innerHTML = `<div class="result-box err">${escapeHtml(e.message)}</div>`;
    }
}

/* ---------- DASHBOARD LOGS (سجل تعديلات الداشبورد) ---------- */

function renderDashLogs() {
    panelHTML(`
        <div class="panel-card">
            <h3>🗒️ سجل تعديلات الداشبورد</h3>
            <div class="section-note">كل تعديل أو إجراء يتم من اللوحة يُسجَّل هنا: من عدّل، ماذا عدّل ومتى — أي شخص يعدّل في اللوحة يبان أثره بكل وضوح.</div>
            <div id="dashlogs-list"><div style="color:var(--muted)">جاري التحميل...</div></div>
            <div style="margin-top:12px">
                <button type="button" class="btn btn-ghost btn-sm" data-action="load-dashboard-logs">🔄 تحديث</button>
            </div>
        </div>
    `);
    loadDashLogs();
}

async function loadDashLogs() {
    const el = $('#dashlogs-list');
    if (!el) return;
    el.innerHTML = '<div style="color:var(--muted)">جاري التحميل...</div>';
    try {
        const data = await api(`/api/server/${currentGuildId}/dashboard-logs`);
        if (!data.logs.length) {
            el.innerHTML = '<div style="color:var(--muted)">لا توجد تعديلات مسجلة بعد.</div>';
            return;
        }
        el.innerHTML = data.logs.map(l => `
            <div class="item">
                <div class="grow">
                    <b>${escapeHtml(l.username)}</b>
                    <div class="small">${escapeHtml(l.action)}${l.details && l.details !== l.action ? ` — ${escapeHtml(l.details)}` : ''}</div>
                </div>
                <div class="small" dir="ltr">${new Date(l.createdAt).toLocaleString('ar')}</div>
            </div>
        `).join('');
    } catch (e) {
        el.innerHTML = `<div style="color:var(--red-bright);font-size:13px">${escapeHtml(e.message)}</div>`;
    }
}

/* ---------- AUTO RESPONSES ---------- */

function renderAutoResponses() {
    const list = GUILD.settings.autoResponses || [];

    panelHTML(`
        <div class="panel-card">
            <h3>🤖 الردود التلقائية</h3>
            <div class="form-grid">
                <div class="form-field"><label>الكلمة (Trigger)</label><input id="ar-trigger" placeholder="مرحبا"></div>
                <div class="form-field"><label>الرد</label><input id="ar-response" placeholder="أهلاً بك!"></div>
            </div>
            <div style="margin-top:8px;display:flex;align-items:center;gap:10px">
                <label class="switch-row" style="border:none;padding:4px 0">
                    <input type="checkbox" id="ar-staff" style="width:auto"> رتبة الستريتر فقط
                </label>
            </div>
            <div style="margin-top:12px">
                <button type="button" class="btn btn-primary btn-sm" data-action="add-auto-response">➕ إضافة</button>
            </div>
        </div>
        <div class="panel-card">
            <h3>📋 الردود الحالية (${list.length})</h3>
            <div class="item-list">
                ${list.length === 0 ? '<div style="color:var(--muted)">لا توجد ردود.</div>' : list.map((r, i) => `
                    <div class="item">
                        <div class="grow">
                            <b>${escapeHtml(r.trigger)}</b>
                            <div class="small">→ ${escapeHtml(r.response)} ${r.staffOnly ? '🔒' : '🌐'}</div>
                        </div>
                                        <button type="button" class="btn btn-danger btn-sm" data-action="remove-auto-response" data-index="${i}">حذف</button>
                    </div>
                `).join('')}
            </div>
        </div>
    `);
}

async function addAutoResponse() {
    const trigger = $('#ar-trigger').value.trim();
    const response = $('#ar-response').value.trim();
    if (!trigger || !response) return toast('أدخل الكلمة والرد', 'err');
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'autoResponses', data: { trigger, response, staffOnly: $('#ar-staff').checked } })
        });
        GUILD.settings = res.settings;
        renderAutoResponses();
        toast('✅ تمت الإضافة');
    } catch (e) { toast(e.message, 'err'); }
}

async function removeAR(i) {
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'autoResponses', data: { removeIndex: i } })
        });
        GUILD.settings = res.settings;
        renderAutoResponses();
        toast('🗑️ تم الحذف');
    } catch (e) { toast(e.message, 'err'); }
}

/* ---------- SHORTCUTS (مجموعة حسب الأمر) ---------- */

const SHORTCUT_COMMANDS = [
    { key: 'ban', label: '🔨 حظر (Ban)', hint: 'اختصار كلمة أو كلمتين أو ثلاث كلمات + المنشن — يبند البوت العضو فوراً. العضو ينكتب منشن أو يوزرنيم أو آيدي.' },
    { key: 'kick', label: '👢 طرد (Kick)', hint: 'اختصار للطرد — العضو منشن أو يوزرنيم أو آيدي.' },
    { key: 'timeout', label: '⏱️ تايم أوت', hint: 'مثال: يسكت @عضو 10m — أو يسكت ahmed 10m (العضو بالاسم والرتبة اختيارية).' },
    { key: 'jail', label: '🔒 سجن', hint: 'سجن فوري — العضو منشن أو يوزرنيم أو آيدي.' },
    { key: 'unjail', label: '🔓 فك السجن', hint: 'فك السجن — العضو منشن أو يوزرنيم أو آيدي.' },
    { key: 'untimeout', label: '🔓 فك التايم أوت', hint: 'يرفع التايم أوت عن العضو — منشن أو يوزرنيم أو آيدي.' },
    { key: 'role-add', label: '🎭 إعطاء رتبة', hint: 'مثال: ر @عضو @رتبة — أو ر ahmed مشرف (اسم الرتبة جزئي كافي) — أو ر @عضو 123456789012345678 (آيدي الرتبة).' },
    { key: 'role-remove', label: '🎭 سحب رتبة', hint: 'نفس حق إعطاء الرتبة: منشن أو اسم الرتبة أو آيديها.' },
    { key: 'unban', label: '🔓 فك الحظر', hint: 'فك الحظر بآيدي العضو.' },
    { key: 'purge', label: '🗑️ مسح الرسائل', hint: 'يمسح رسائل الشات بالعدد.' },
    { key: 'lock', label: '🔒 قفل روم', hint: 'يقفل الروم المؤلَّف.' },
    { key: 'unlock', label: '🔓 فتح روم', hint: 'يفتح الروم المؤلَّف.' }
];

function shortcutsFor(command) {
    return (GUILD.settings.shortcuts || [])
        .map((s, i) => ({ ...s, i }))
        .filter(s => s.command === command);
}

// ⭐ شبكة أمان: أي اختصار سويته من أمر سلاش ما كان موجود بـ SHORTCUT_COMMANDS
// (مثلاً أمر جديد نضيفه للسلاش لاحقاً) يظهر هنا بدال ما يختفي من الموقع.
function orphanShortcutGroups() {
    const known = new Set(SHORTCUT_COMMANDS.map(c => c.key));

    const orphans = [...new Set(
        (GUILD.settings.shortcuts || [])
            .map(s => s?.command)
            .filter(c => c && !known.has(c))
    )];

    if (!orphans.length) return '';

    return orphans.map(key => {
        const list = shortcutsFor(key);
        const open = openScGroup === key;
        return `
            <div class="panel-card sc-group">
                <button type="button" class="sc-group-head" data-action="toggle-shortcut-group" data-command="${escapeHtml(key)}">
                    <span>⚙️ ${escapeHtml(key)}</span>
                    <span class="sc-badge">${list.length}</span>
                    <span class="sc-arrow ${open ? 'open' : ''}">▼</span>
                </button>
                <div class="sc-group-body ${open ? 'open' : ''}" id="sc-body-${escapeHtml(key)}">
                    <div style="color:var(--muted);font-size:12px;margin-bottom:10px">أمر إداري أضافه أمر سلاش — ما له وصف جاهز بالموقع.</div>
                    <div class="sc-chips" id="sc-list-${escapeHtml(key)}">
                        ${list.map(s => `
                            <span class="sc-chip">
                                ${escapeHtml(s.name)}
                                <button type="button" class="sc-chip-x" data-action="remove-shortcut" data-command="${escapeHtml(key)}" data-index="${s.i}" title="حذف">✖</button>
                            </span>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

let openScGroup = 'ban';

function shortcutGroupsHTML() {
    return SHORTCUT_COMMANDS.map(c => {
        const list = shortcutsFor(c.key);
        const open = openScGroup === c.key;
        return `
            <div class="panel-card sc-group">
                <button type="button" class="sc-group-head" data-action="toggle-shortcut-group" data-command="${c.key}">
                    <span>${c.label}</span>
                    <span class="sc-badge">${list.length}</span>
                    <span class="sc-arrow ${open ? 'open' : ''}">▼</span>
                </button>
                <div class="sc-group-body ${open ? 'open' : ''}" id="sc-body-${c.key}">
                    <div style="color:var(--muted);font-size:12px;margin-bottom:10px">${c.hint}</div>
                    <div class="sc-chips" id="sc-list-${c.key}">
                        ${
                            list.length === 0
                                ? '<span class="sc-chip sc-chip-empty">لا توجد اختصارات</span>'
                                : list.map(s => `
                                    <span class="sc-chip">
                                        ${escapeHtml(s.name)}
                                        <button type="button" class="sc-chip-x" data-action="remove-shortcut" data-command="${c.key}" data-index="${s.i}" title="حذف">✖</button>
                                    </span>
                                `).join('')
                        }
                    </div>
                    <div style="display:flex;gap:8px;margin-top:12px;align-items:center">
                        <input id="sc-input-${c.key}" class="grow" placeholder="اكتب الاختصار... مثال: بان بسرعة (كلمة / كلمتين / ثلاث كلمات)">
                        <button type="button" class="btn btn-primary btn-sm" data-action="add-shortcut" data-command="${c.key}">➕ إضافة</button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function toggleScGroup(key) {
    openScGroup = openScGroup === key ? '' : key;
    renderShortcuts();
}

function renderShortcuts() {
    panelHTML(`
        <div class="panel-card">
            <h3>⚡ الاختصارات حسب الأمر</h3>
            <div class="section-note">اضغط على أي أمر إداري تنزل تحت مباشرة قائمته: تشوف اختصاراته وتضيف اختصارك — كلمة واحدة، كلمتين أو ثلاث كلمات. لما يكتب العضو الاختصار في الروم ينفذ البوت الأمر فوراً.<br>كل شي تسويه بأمر سلاش (<code>/shortcut</code> أو الردود التلقائية) يظهر هنا مباشرة.</div>
        </div>
        ${shortcutGroupsHTML()}
        ${orphanShortcutGroups()}
    `);
}

async function addShortcutFor(command) {
    const name = $('#sc-input-' + command).value.trim();
    if (!name) return toast('اكتب اسم الاختصار أولاً', 'err');
    if (name.split(/\s+/).length > 3) return toast('الاختصار بحد أقصى ثلاث كلمات', 'err');
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'shortcuts', data: { name, command } })
        });
        GUILD.settings = res.settings;
        renderShortcuts();
        toast('✅ تمت إضافة الاختصار');
    } catch (e) { toast(e.message, 'err'); }
}

async function removeShortcutFor(command, i) {
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'shortcuts', data: { removeIndex: i } })
        });
        GUILD.settings = res.settings;
        renderShortcuts();
        toast('🗑️ تم حذف الاختصار');
    } catch (e) { toast(e.message, 'err'); }
}

/* ---------- LEVELS ---------- */

function renderLevels() {
    const ls = GUILD.settings.levelSettings || {};
    const rewards = (ls.rewards && typeof ls.rewards === 'object')
        ? (ls.rewards instanceof Map ? [...ls.rewards.entries()] : Object.entries(ls.rewards))
        : [];

    const roleName = id => GUILD.roles.find(r => String(r.id) === String(id))?.name || 'رتبة محذوفة';

    panelHTML(`
        <div class="panel-card">
            <h3>🏆 نظام المستويات</h3>
            <div class="switch-row">
                <div class="txt"><b>تفعيل المستويات</b><small>عدّاد الرسائل والمستويات لكل عضو</small></div>
                <label class="toggle">
                    <input type="checkbox" id="lv-enabled" ${ls.enabled ? 'checked' : ''}>
                    <span class="slider"></span>
                </label>
            </div>
            <div class="form-field" style="margin-top:10px">
                <label>عدد الرسائل لكل مستوى</label>
                <input type="number" id="lv-messages" min="1" value="${ls.messagesPerLevel || 50}">
            </div>
        </div>

        <div class="panel-card">
            <h3>🎁 مكافآت المستويات</h3>
            <div class="form-grid">
                <div class="form-field"><label>المستوى</label><input type="number" id="rw-level" min="1" value="5"></div>
                <div class="form-field">
                    <label>الرتبة المكافأة</label>
                    <select id="rw-role">
                        ${GUILD.roles.map(r => `<option value="${r.id}">${escapeHtml(r.name)}</option>`).join('')}
                    </select>
                </div>
            </div>
            <div style="margin-top:12px">
                <button type="button" class="btn btn-primary btn-sm" data-action="add-reward">➕ إضافة مكافأة</button>
            </div>
            <div class="item-list" style="margin-top:14px">
                ${rewards.length === 0 ? '<div style="color:var(--muted)">لا توجد مكافآت.</div>' : rewards.map(([lv, role]) => `
                    <div class="item">
                        <div class="grow"><b>المستوى ${lv}</b> <span class="small">→ ${escapeHtml(roleName(role))}</span></div>
                        <button type="button" class="btn btn-danger btn-sm" data-action="remove-reward" data-level="${lv}">حذف</button>
                    </div>
                `).join('')}
            </div>
            <div style="margin-top:14px"><button type="button" class="btn btn-primary" data-action="save-levels">💾 حفظ</button></div>
        </div>
    `);
}

async function saveLevels() {
    const data = {
        enabled: $('#lv-enabled').checked,
        messagesPerLevel: Number($('#lv-messages').value) || 50
    };
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'levelSettings', data })
        });
        GUILD.settings = res.settings;
        toast('✅ تم الحفظ');
    } catch (e) { toast(e.message, 'err'); }
}

async function addReward() {
    const level = $('#rw-level').value;
    const role = $('#rw-role').value;
    if (!level || !role) return toast('أدخل المستوى والرتبة', 'err');
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'levelSettings', data: { rewardLevel: level, rewardRole: role } })
        });
        GUILD.settings = res.settings;
        renderLevels();
        toast('✅ تمت الإضافة');
    } catch (e) { toast(e.message, 'err'); }
}

async function removeReward(lv) {
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'levelSettings', data: { removeRewardLevel: lv } })
        });
        GUILD.settings = res.settings;
        renderLevels();
        toast('🗑️ تم الحذف');
    } catch (e) { toast(e.message, 'err'); }
}

/* ---------- AUTO ROLE ---------- */

function renderAutoRole() {
    const ar = GUILD.settings.autoRole || {};

    panelHTML(`
        <div class="panel-card">
            <h3>🎭 الرتبة التلقائية</h3>
            <div class="section-note">تُعطى رتبة تلقائياً لأي عضو جديد يدخل السيرفر.</div>
            <div class="form-field" style="margin-bottom:12px">
                <label>الرتبة التلقائية</label>
                <select id="arole-role">
                    <option value="">— إيقاف —</option>
                    ${GUILD.roles.map(r =>
                        `<option value="${r.id}" ${String(ar.roleId) === String(r.id) ? 'selected' : ''}>${escapeHtml(r.name)}</option>`
                    ).join('')}
                </select>
            </div>
            <div class="switch-row">
                <div class="txt"><b>مفعّل</b><small>${ar.enabled ? 'الرتبة تُعطى تلقائياً' : 'معطل'}</small></div>
                <label class="toggle">
                    <input type="checkbox" id="arole-enabled" ${ar.enabled ? 'checked' : ''}>
                    <span class="slider"></span>
                </label>
            </div>
            <div style="margin-top:14px">
                <button type="button" class="btn btn-primary" data-action="save-auto-role">💾 حفظ</button>
            </div>
        </div>
    `);
}

async function saveAutoRole() {
    const data = {
        enabled: $('#arole-enabled').checked,
        roleId: $('#arole-role').value || null
    };
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'autoRole', data })
        });
        GUILD.settings = res.settings;
        toast('✅ تم الحفظ');
    } catch (e) { toast(e.message, 'err'); }
}

/* ---------- WHITELIST (راعي البوت أو راعي السيرفر فقط) ---------- */

let WL_NAMES = {};

async function loadWhitelistNames(ids) {
    const missing = ids.filter(id => !WL_NAMES[id]);
    for (const id of missing) {
        try {
            const res = await api(`/api/server/${currentGuildId}/members?q=${encodeURIComponent(id)}`);
            const hit = (res.members || []).find(m => m.id === id);
            WL_NAMES[id] = hit ? (hit.username || hit.tag || id) : null;
        } catch { WL_NAMES[id] = null; }
    }
}

function renderWhitelist() {
    const list = GUILD.settings.whitelist || [];

    if (!GUILD.canManageWhitelist) {
        panelHTML(`
            <div class="panel-card" style="border-color:var(--red-dark)">
                <h3>🔒 الوايت ليست</h3>
                <div class="section-note">
                    هذي الصفحة للـ <b>راعي البوت</b> أو <b>راعي السيرفر</b> فقط.
                    حتى بأمر <code>/whitelist</code> ما يقدر يستخدمها غير المالك.
                </div>
            </div>
        `);
        return;
    }

    panelHTML(`
        <div class="panel-card">
            <h3>🟢 الوايت ليست</h3>
            <div class="section-note">
                أعضاء الوايت ليست تتجاهلهم الحماية — أضف مالك السيرفر والمشرفين الموثوقين.
                <br>🔒 <b>أنت فقط (راعي البوت أو راعي السيرفر)</b> تقدر تضيف أو تحذف من هنا.
                <br>⛔ <b>حماية الاختصار ما تتجاوز</b> الوايت ليست (إلا إذا سمحت من إعداداتها).
            </div>
            <div class="form-field">
                <label>آيدي العضو</label>
                <input id="wl-id" placeholder="آيدي الديسكورد">
            </div>
            <div style="margin-top:12px">
                <button type="button" class="btn btn-primary btn-sm" data-action="add-whitelist">➕ إضافة</button>
            </div>
        </div>
        <div class="panel-card">
            <h3>📋 القائمة (${list.length})</h3>
            <div class="item-list">
                ${list.length === 0 ? '<div style="color:var(--muted)">القائمة فارغة.</div>' : list.map(id => `
                    <div class="item">
                        <div class="grow">
                            <b>${escapeHtml(WL_NAMES[id] || id)}</b>
                            <small style="display:block;color:var(--muted);font-size:11px">${escapeHtml(id)}</small>
                        </div>
                        <button type="button" class="btn btn-danger btn-sm" data-action="remove-whitelist" data-user-id="${id}">حذف</button>
                    </div>
                `).join('')}
            </div>
        </div>
    `);

    loadWhitelistNames(list).then(() => {
        if (currentTab === 'whitelist') renderWhitelist();
    });
}

async function addWhitelist() {
    const id = $('#wl-id').value.trim();
    if (!id) return toast('أدخل الآيدي', 'err');
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'whitelist', data: { mode: 'add', userId: id } })
        });
        GUILD.settings = res.settings;
        renderWhitelist();
        toast('✅ تمت الإضافة');
    } catch (e) { toast(e.message, 'err'); }
}

async function removeWhitelist(id) {
    try {
        const res = await api(`/api/server/${currentGuildId}/settings`, {
            method: 'POST',
            body: JSON.stringify({ section: 'whitelist', data: { mode: 'remove', userId: id } })
        });
        GUILD.settings = res.settings;
        renderWhitelist();
        toast('🗑️ تم الحذف');
    } catch (e) { toast(e.message, 'err'); }
}

function dashboardAction(trigger) {
    const data = trigger.dataset;

    switch (data.action) {
        case 'refresh-servers': return () => refreshServers();
        case 'go-servers': return () => {
            history.pushState(null, '', '#servers');
            return renderServers();
        };
        case 'logout': return () => logout();
        case 'open-server': return () => {
            const guildId = String(data.serverId || '').trim();
            if (!guildId) return;
            history.pushState(null, '', `#server/${guildId}`);
            return renderServer(guildId);
        };
        case 'show-servers': return () => {
            history.pushState(null, '', '#servers');
            return renderServers();
        };
        case 'switch-tab': return () => switchTab(data.tab);
        case 'quick-action': return () => quickAction(data.command, data.userId);
        case 'embed': return () => doEmbed();
        case 'save-protection': return () => updateProtection();
        case 'toggle-prot-card': return () => toggleProtectionCard(data.key);
        case 'invite-load': return () => loadServerInvites();
        case 'invite-auto': return () => assignInvite('auto');
        case 'invite-assign': return () => assignInvite('assign', { code: data.code });
        case 'invite-create': return () => {
            const channelId = $('#invite-create-channel')?.value || '';
            if (!channelId) return toast('اختر روم نصي أول', 'err');
            return assignInvite('create', { channelId });
        };
        case 'open-all-protections': return () => {
            Object.keys(PROTECTION_METRICS).forEach(key => setProtectionCard(key, true));
        };
        case 'close-all-protections': return () => {
            Object.keys(PROTECTION_METRICS).forEach(key => setProtectionCard(key, false));
        };
        case 'embed-field-add': return () => {
            $('#embed-fields').insertAdjacentHTML('beforeend', embedFieldsHTML([{ name: '', value: '', inline: true }]));
            renderEmbedPreview($('#embed-color').value);
        };
        case 'embed-field-remove': return (e) => {
            e.target.closest('.embed-field-row')?.remove();
            renderEmbedPreview($('#embed-color').value);
        };
        case 'ticket-option-add': return () => addTicketOption();
        case 'ticket-option-remove': return (e) => removeTicketOption(Number(e.target.dataset.index));
        case 'ticket-option-up': return (e) => moveTicketOption(Number(e.target.dataset.index), -1);
        case 'ticket-option-down': return (e) => moveTicketOption(Number(e.target.dataset.index), 1);
        case 'save-tickets': return () => saveTickets();
        case 'send-ticket-panel': return () => sendTicketPanel();
        case 'save-welcome': return () => saveWelcome();
        case 'save-logs': return () => saveLogs();
        case 'load-dashboard-logs': return () => loadDashLogs();
        case 'add-auto-response': return () => addAutoResponse();
        case 'remove-auto-response': return () => removeAR(Number(data.index));
        case 'toggle-shortcut-group': return () => toggleScGroup(data.command);
        case 'add-shortcut': return () => addShortcutFor(data.command);
        case 'remove-shortcut': return () => removeShortcutFor(data.command, Number(data.index));
        case 'add-reward': return () => addReward();
        case 'remove-reward': return () => removeReward(data.level);
        case 'save-levels': return () => saveLevels();
        case 'save-auto-role': return () => saveAutoRole();
        case 'add-whitelist': return () => addWhitelist();
        case 'remove-whitelist': return () => removeWhitelist(data.userId);
        default: return null;
    }
}

document.addEventListener('click', event => {
    const trigger = event.target.closest('[data-action]');
    if (!trigger || trigger.disabled) return;

    const action = dashboardAction(trigger);
    if (!action) return;
    event.preventDefault();

    Promise.resolve()
        .then(() => action(event))
        .catch(error => toast(error?.message || 'حدث خطأ، أعد المحاولة.', 'err'));
});

document.addEventListener('change', event => {
    // 🚨 حماية النصب: تظليل القاعدة المفعلة
    const rule = event.target.dataset?.scamRule;
    if (rule) {
        event.target.closest('[data-scam-rule-row]')?.classList.toggle('on', event.target.checked);
        return;
    }

    const key = event.target.dataset?.protectionKey;
    if (!key) return;
    protToggle(key, event.target.checked).catch(error => toast(error.message, 'err'));
});

/* ============================================================
   INIT
   ============================================================ */

boot();
