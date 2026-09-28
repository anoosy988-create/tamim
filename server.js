const express = require('express');
const crypto = require('crypto');
const https = require('https');
const path = require('path');

const SESSION_TTL = 7 * 24 * 60 * 60 * 1000;   // أسبوع
const OAUTH_STATE_TTL = 10 * 60 * 1000;   // 10 دقائق
const SERVERS_CACHE_TTL = 30 * 60 * 1000;      // 30 دقيقة

    const DISCORD_API = 'https://discord.com/api/v10';
    const DISCORD_OAUTH_URL = 'https://discord.com/oauth2/authorize';

// الصلاحيات المطلوبة للدخول: identify + guilds (لجلب قائمة سيرفرات المستخدم)
const OAUTH_SCOPES = 'identify guilds';

// صلاحية Administrator في ديسكورد (bit 3 = 0x8) — البت اللي نفلتر عليه
const PERM_ADMINISTRATOR = 0x8;


// العقوبات المسموحة لكل مقياس حماية (نفسها في index.js)
const PROTECTION_ACTIONS = ['ban', 'kick', 'timeout', 'jail', 'removeroles'];

// ⚡ أوامر الاختصارات اللي تقدر تنفَّذ عقوبة على عضو (نفسها في index.js/app.js)
const PUNISH_SHORTCUT_COMMANDS = ['ban', 'kick', 'timeout', 'jail'];

// ⚡ الكوكي الوحيد للجلسة — نفس الاسم اللي كان يطلع في sessionCookie()
const SESSION_COOKIE_NAME = 'dash_session';

const serversCache = new Map();                // userId -> { guilds, cachedAt }
const oauthStates = new Map();                 // state -> { createdAt }
const accessCache = new Map();                 // userId -> { revoked, at }
const ACCESS_CACHE_TTL = 15 * 1000;            // 15 ثانية

// ======================================================
// فلترة سيرفرات المستخدم: نُبقي سيرفرات Administrator فقط
// العملية المطلوبة: (guild.permissions & 0x8) === 0x8
// ======================================================
// 🔒 عزل بين المستخدمين: ما نعرض أي سيرفر إلا لو:
//    1) OAuth قال إن المستخدم عنده Administrator (أو هو المالك)، و
//    2) البوت داخل السيرفر فعلياً (لأنه بدونه ما نقدر نعدّل أي شي)
function filterAdminGuilds(rawGuilds, client) {
    if (!Array.isArray(rawGuilds)) return [];

    return rawGuilds
        .filter(g => g && (g.owner === true || (Number(g.permissions) & PERM_ADMINISTRATOR) === PERM_ADMINISTRATOR))
        .filter(g => !client || client.guilds.cache.has(String(g.id)))
        .map(g => ({
            id: String(g.id),
            name: g.name || 'سيرفر',
            icon: g.icon ? `https://cdn.discordapp.com/icons/${g.id}/${g.icon}.png?size=256` : null,
            owner: g.owner === true,
            permissions: String(g.permissions ?? '0'),
            hasAdministrator: (Number(g.permissions) & PERM_ADMINISTRATOR) === PERM_ADMINISTRATOR,
            // أعداد تقريبية يرسلها ديسكورد مع قائمة السيرفرات
            approximate_member_count: Number.isFinite(g.approximate_member_count) ? g.approximate_member_count : null,
            approximate_presence_count: Number.isFinite(g.approximate_presence_count) ? g.approximate_presence_count : null
        }));
}

// ======================================================
// الجلسات: كوكي موقّع + بيانات الجلسة محفوظة على السيرفر
// (بديل عن express-session بدون أي حزمة خارجية — كانت ناقصة وتطيّر الداشبورد)
// ======================================================

// مفتاح توقيع الجلسات: يُقرأ من .env أو يُولَّد عشوائياً مرة واحدة عند التشغيل
const EPHEMERAL_SESSION_SECRET = crypto.randomBytes(32).toString('hex');

function sessionSecret() {
    return String(
        process.env.SESSION_SECRET ||
        process.env.DASHBOARD_CLIENT_SECRET ||
        process.env.CLIENT_SECRET ||
        process.env.DISCORD_CLIENT_SECRET ||
        EPHEMERAL_SESSION_SECRET
    );
}

function signToken(payload) {
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', sessionSecret()).update(body).digest('base64url');
    return `${body}.${sig}`;
}

// يفك الكوكي الموقّع ويرجّع محتواه (أو null إذا الكوكي مزوّر/مكسور)
function readSignedToken(token) {
    if (!token || typeof token !== 'string' || !token.includes('.')) return null;

    const [body, sig] = token.split('.');

    if (!body || !sig) return null;

    const expected = crypto.createHmac('sha256', sessionSecret()).update(body).digest('base64url');

    const given = Buffer.from(String(sig));
    const real = Buffer.from(expected);
    if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) return null;

    try {
        return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    } catch {
        return null;
    }
}

function parseCookies(req) {
    const out = {};
    const header = req.headers.cookie || '';
    for (const part of header.split(';')) {
        const i = part.indexOf('=');
        if (i === -1) continue;
        out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    return out;
}

// كل المسارات تقرا الجلسة من هنا (الـ middleware يملاها قبل أي route)
function hasSession(req) {
    const data = req?.session?.user;

    if (!data?.userId) return null;

    return { userId: String(data.userId), guilds: data.guilds || [] };
}

// ======================================================
// الجلسات: كوكي موقّع يحوي آدي جلسة عشوائي (sid)، والبيانات محفوظة على السيرفر
// السبب: كان الملف يطلب express-session وهي غير مثبّتة، فالداشبورد كان
// يطير بـ "Cannot find module 'express-session'" أول ما ينفّذ.
// فايدة التخزين على السيرفر: "تسجيل الخروج" يمسح الجلسة فعلياً
// (الكوكي لحاله ما يقدر يلغي، لأن التوقيع يظل صحيح).
// ملاحظة: الكوكي القديم (اللي كان يحمل userId) ما ننقله — كان بearer token
// يقدر يتقلّد وما ينفع إلغاؤه. من يدفع تسجيل دخول جديد تلقائياً يرجع.
// ======================================================

const sessionStore = new Map();                // sid -> { data, expiresAt }

function sessionCookie(req, token, maxAgeSeconds) {
    const secure = req.secure || String(req.headers['x-forwarded-proto'] || '').includes('https');
    return `dash_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}${secure ? '; Secure' : ''}`;
}

// ينظّف الجلسات المنتهية كل 10 دقائق (عشان الـ Map ما يكبر للأبد)
const sessionSweeper = setInterval(() => {
    const now = Date.now();

    for (const [sid, record] of sessionStore) {
        if (record.expiresAt <= now) sessionStore.delete(sid);
    }

    for (const [state, record] of oauthStates) {
        if (now - record.createdAt > OAUTH_STATE_TTL) oauthStates.delete(state);
    }
}, 10 * 60 * 1000);

sessionSweeper.unref?.();

// يقرأ الجلسة من الكوكي الموقّع ويعيد req.session (نفس الواجهة اللي تستخدمها المسارات)
function createSession(options = {}) {
    const name = String(options.name || SESSION_COOKIE_NAME);
    const maxAge = Number(options?.cookie?.maxAge) || SESSION_TTL;
    const maxAgeSeconds = Math.floor(maxAge / 1000);

    return function sessionMiddleware(req, res, next) {
        const token = parseCookies(req)[name];
        const payload = token ? readSignedToken(token) : null;

        // ما نقبل أي شي غير sid — التوقيع لحاله ما يكفي بدون سجل بالمخزن
        let sid = typeof payload?.sid === 'string' && payload.sid.length >= 16
            ? payload.sid
            : null;

        let record = sid ? sessionStore.get(sid) : null;

        // جلسة منتهية أو ما موجودة = نبدأ جلسة جديدة فاضية
        if (record && record.expiresAt <= Date.now()) {
            sessionStore.delete(sid);
            record = null;
        }

        if (!record) sid = null;

        const session = record ? { ...record.data } : {};
        let destroyed = false;

        session.destroy = function (callback) {
            destroyed = true;

            if (sid) sessionStore.delete(sid);

            for (const key of Object.keys(session)) {
                if (typeof session[key] !== 'function') delete session[key];
            }

            res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
            res.clearCookie(name);

            if (typeof callback === 'function') callback();
        };

        req.session = session;

        // نحفظ الجلسة قبل ما ينضبط الرد (نفس الطريقة اللي تسويها express-session)
        let committed = false;
        const originalEnd = res.end;

        res.end = function (...args) {
            if (!committed) {
                committed = true;

                try {
                    if (!destroyed) {
                        const data = {};

                        for (const key of Object.keys(session)) {
                            if (typeof session[key] !== 'function') data[key] = session[key];
                        }

                        // ما ننشئ سجل إلا إذا فيه بيانات فعلاً (يعادل saveUninitialized: false)
                        if (Object.keys(data).length) {
                            if (!sid) sid = crypto.randomBytes(24).toString('base64url');

                            sessionStore.set(sid, { data, expiresAt: Date.now() + maxAge });
                            res.setHeader(
                                'Set-Cookie',
                                sessionCookie(req, signToken({ sid, at: Date.now() }), maxAgeSeconds)
                            );
                        }
                    }
                } catch (e) {
                    console.error('dashboard session save error:', e.message);
                }
            }

            return originalEnd.apply(this, args);
        };

        next();
    };
}

// طلب JSON من ديسكورد عبر HTTPS
// form: true → يرسل البيانات application/x-www-form-urlencoded (المطلوب لنقطة oauth2/token)
function discordRequest(url, { method = 'GET', body = null, headers = {}, form = false } = {}) {
    return new Promise((resolve, reject) => {
        let parsed;
        try {
            parsed = new URL(url);
        } catch {
            reject(new Error('رابط غير صالح'));
            return;
        }

        const isForm = form === true;
        const payload = body
            ? Buffer.from(isForm
                ? Object.entries(body)
                    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v ?? '')}`)
                    .join('&')
                : JSON.stringify(body))
            : null;

        const request = https.request(
            {
                method,
                hostname: parsed.hostname,
                path: `${parsed.pathname}${parsed.search}`,
                headers: {
                    'Content-Type': isForm
                        ? 'application/x-www-form-urlencoded'
                        : 'application/json',
                    'User-Agent': 'CypherDashboard/1.0',
                    ...(payload ? { 'Content-Length': payload.length } : {}),
                    ...headers
                }
            },
            response => {
                const chunks = [];
                response.on('data', chunk => chunks.push(chunk));
                response.on('end', () => {
                    const raw = Buffer.concat(chunks).toString('utf8');
                    let data = null;
                    try { data = raw ? JSON.parse(raw) : null; } catch {}
                    if (Number(response.statusCode) >= 400) {
                        reject(new Error(data?.error_description || data?.error || `Discord ${response.statusCode}`));
                        return;
                    }
                    resolve(data);
                });
            }
        );

        request.setTimeout(10000, () => request.destroy(new Error('انتهت مهلة الاتصال بديسكورد')));
        request.on('error', reject);
        if (payload) request.write(payload);
        request.end();
    });
}

function safeLogValue(value, maxLength = 500) {
    return String(value || '').replace(/[\r\n`]/g, ' ').trim().slice(0, maxLength) || 'غير معروف';
}

function describeDevice(userAgent) {
    const value = String(userAgent || '');
    let browser = 'متصفح غير معروف';

    if (/Edg(?:A|iOS)?\//i.test(value)) browser = 'Microsoft Edge';
    else if (/OPR\/|Opera\//i.test(value)) browser = 'Opera';
    else if (/Firefox\/|FxiOS\//i.test(value)) browser = 'Firefox';
    else if (/SamsungBrowser\//i.test(value)) browser = 'Samsung Internet';
    else if (/Chrome\/|CriOS\//i.test(value)) browser = 'Google Chrome';
    else if (/Safari\//i.test(value)) browser = 'Safari';

    let os = 'نظام غير معروف';
    if (/Windows/i.test(value)) os = 'Windows';
    else if (/Android/i.test(value)) os = 'Android';
    else if (/iPhone|iPad|iPod/i.test(value)) os = 'iOS / iPadOS';
    else if (/Macintosh|Mac OS X/i.test(value)) os = 'macOS';
    else if (/Linux/i.test(value)) os = 'Linux';

    let type = 'جهاز غير معروف';
    if (/iPad|Tablet|PlayBook|Silk/i.test(value)) type = 'جهاز لوحي';
    else if (/Mobile|iPhone|iPod|Android/i.test(value)) type = 'هاتف';
    else if (/Windows|Macintosh|Mac OS X|Linux/i.test(value)) type = 'حاسوب';

    return `المتصفح: ${browser} • النظام: ${os} • النوع: ${type}`;
}

// استخراج الآيبي الحقيقي للزائر (مع مراعاء X-Forwarded-For)
function clientIp(req) {
    const forwarded = String(req.headers['x-forwarded-for'] || '')
        .split(',')
        .map(value => value.trim())
        .filter(Boolean)[0];

    const raw = forwarded ||
        String(req.headers['x-real-ip'] || '').trim() ||
        req.ip ||
        req.socket?.remoteAddress ||
        'غير معروف';
    const clean = String(raw).replace(/^::ffff:/i, '').trim();

    return safeLogValue(clean, 45);
}

function fallbackAvatarSvg() {
    return `
        <svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
            <defs>
                <linearGradient id="background" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0" stop-color="#8f1d1d"/>
                    <stop offset="1" stop-color="#2a1010"/>
                </linearGradient>
            </defs>
            <rect width="512" height="512" rx="128" fill="url(#background)"/>
            <path d="M256 84 406 136v112c0 96-61 157-150 190-89-33-150-94-150-190V136L256 84Z" fill="#2b0f0f" stroke="#ff5252" stroke-width="16"/>
            <path d="m256 153 28 56 62 9-45 44 11 62-56-30-56 30 11-62-45-44 62-9 28-56Z" fill="#d63d3d"/>
        </svg>
    `;
}

function fetchDiscordImage(url, redirects = 0) {
    return new Promise((resolve, reject) => {
        let parsed;
        try {
            parsed = new URL(url);
        } catch {
            reject(new Error('Invalid avatar URL'));
            return;
        }

        if (parsed.protocol !== 'https:') {
            reject(new Error('Unsupported avatar protocol'));
            return;
        }

        if (redirects > 3) {
            reject(new Error('Too many avatar redirects'));
            return;
        }

        const request = https.get(parsed, {
            headers: {
                'User-Agent': 'CypherDashboard/1.0',
                Accept: 'image/avif,image/webp,image/png,image/jpeg,image/gif'
            }
        }, response => {
            const status = Number(response.statusCode || 0);
            const location = response.headers.location;

            if (status >= 300 && status < 400 && location) {
                response.resume();
                fetchDiscordImage(new URL(location, parsed).toString(), redirects + 1)
                    .then(resolve, reject);
                return;
            }

            if (status !== 200) {
                response.resume();
                reject(new Error(`Avatar request failed with status ${status}`));
                return;
            }

            const contentLength = Number(response.headers['content-length'] || 0);
            if (contentLength > 5 * 1024 * 1024) {
                response.resume();
                reject(new Error('Avatar is too large'));
                return;
            }

            const chunks = [];
            let size = 0;

            response.on('data', chunk => {
                size += chunk.length;
                if (size <= 5 * 1024 * 1024) {
                    chunks.push(chunk);
                } else {
                    request.destroy(new Error('Avatar is too large'));
                }
            });
            response.on('end', () => {
                if (size > 5 * 1024 * 1024) return;
                resolve({
                    body: Buffer.concat(chunks),
                    contentType: String(response.headers['content-type'] || 'image/png')
                });
            });
            response.on('error', reject);
        });

        request.setTimeout(7000, () => request.destroy(new Error('Avatar request timed out')));
        request.on('error', reject);
    });
}

module.exports = function setupDashboard(app, deps = {}) {
    // ======================================================
    // مصدر الاعتماديات
    // ======================================================
    // 1) mounted   : index.js يمرّر deps جاهزة (البوت هو اللي يشغّل)
    // 2) standalone: ما جات deps → نبنيها من lib/bot-context.js
    //    (الداشبورد يشتغل لحاله على استضافة ثانية بتوكنه و OWNER_IDS تبعه)
    const injected = deps || {};
    const standalone = !injected.client;

    const ctxLib = standalone ? require('./lib/bot-context.js') : null;
    const resolved = standalone
        ? ctxLib.buildDeps({ client: injected.client, tickets: injected.tickets })
        : injected;

    // نكمل أي dep ناقص من lib حتى لو بعضهم جاي من البوت
    for (const depName of [
        'getSettings', 'ensureProtections', 'sendLog', 'jailMember', 'unjailMember',
        'isServerAdmin', 'memberHasStaffRole', 'hasStaffAccess', 'normalizeText',
        'getMember', 'getJailRole'
    ]) {
        if (resolved[depName] === undefined && ctxLib?.[depName]) {
            resolved[depName] = ctxLib[depName];
        }
    }

    const {
        client,
        getSettings,
        ensureProtections,
        sendLog,
        jailMember,
        unjailMember,
        isServerAdmin,
        memberHasStaffRole,
        DashboardUser,
        DashboardLog,
        STAFF_ROLE_NAME,
        OWNER_ID,
        normalizeText,
        EmbedBuilder,
        ChannelType
    } = resolved;

    // التكتات: comes من البوت في الوضع mounted، أو اختياري في standalone.
    // (لما يكون مشغّل لحاله على استضافة ثانية بدون وحدة تكتات، نتجاهل
    //  الخطأ بدل ما نكسر الداشبورد كله)
    const tickets = resolved.tickets || null;

    if (standalone) {
        console.log(
            '[panel] ⚙️  تشغيل مستقل (standalone) — الداشبورد يبني اعتماداته بنفسه'
        );
    }

    // يتحقق من عقوبة "shortcut:<name>": يرجّع الصيغة الموحّدة لو الاختصار
    // محفوظ وأمره يقدر يعاقب، وإلا يرجّع null (ما نخزّنش إعدادات معطوبة)
    function resolveShortcutAction(value, settings) {
        if (typeof value !== 'string' || !value.startsWith('shortcut:')) return null;

        const name = value.slice('shortcut:'.length).trim();
        if (!name) return null;

        const saved = (settings?.shortcuts || []).find(
            s => normalizeText(String(s?.name || '')) === normalizeText(name)
        );

        if (!saved?.command) return null;
        if (!PUNISH_SHORTCUT_COMMANDS.includes(saved.command)) return null;

        return `shortcut:${name}`;
    }

    app.set('trust proxy', 1);

    const publicDir = path.join(__dirname, 'public');
    let botAvatarCache = null;

    // ======================================================
    // الجلسات: كوكي موقّع (بدون حزم خارجية)
    // ======================================================
    app.use(
        createSession({
            name: SESSION_COOKIE_NAME,
            cookie: {
                httpOnly: true,
                sameSite: 'lax',
                secure: false,          // يتفعل تلقائياً عبر req.secure في الكوكي الموقّع
                maxAge: SESSION_TTL
            }
        })
    );

    // ======================================================
    // HELPERS
    // ======================================================

    function sendFallbackAvatar(res) {
        res.set({
            'Cache-Control': 'public, max-age=300',
            'Content-Type': 'image/svg+xml; charset=utf-8',
            'X-Content-Type-Options': 'nosniff'
        });
        res.status(200).send(fallbackAvatarSvg());
    }

    function botSnapshot() {
        const guilds = [...client.guilds.cache.values()];
        const user = client.user || null;
        const ready = Boolean(user && (typeof client.isReady === 'function' ? client.isReady() : true));
        const readyTimestamp = Number(client.readyTimestamp || 0);
        const uptime = Number(client.uptime || (readyTimestamp ? Date.now() - readyTimestamp : 0));
        const members = guilds.reduce((total, guild) => total + Number(guild.memberCount || 0), 0);

        return {
            ready,
            status: ready ? 'online' : 'connecting',
            username: user?.username || process.env.BOT_NAME || 'Cypher Security',
            tag: user?.tag || process.env.BOT_NAME || 'Cypher Security',
            avatar: '/api/bot/avatar',
            avatarVersion: user ? `${user.id}:${user.avatar || 'default'}` : null,
            id: user?.id || null,
            uptimeMs: ready ? Math.max(0, uptime) : 0,
            readyAt: readyTimestamp ? new Date(readyTimestamp).toISOString() : null,
            ping: Number.isFinite(client.ws?.ping) ? Math.max(0, Math.round(client.ws.ping)) : null,
            servers: guilds.length,
            members,
            gateway: client.ws?.status || null,
            inviteUrl: user
                ? `https://discord.com/oauth2/authorize?client_id=${encodeURIComponent(user.id)}&permissions=8&scope=bot%20applications.commands`
                : null
        };
    }

    // نكتشف الرابط العام من أول طلب — لازم قبل أي route عشان يلتقط كل شي
    app.use((req, res, next) => {
        try {
            const host = String(req.get('host') || '').trim();

            if (host) {
                const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'https').split(',')[0].trim();
                const detected = `${proto}://${host}`.replace(/\/+$/, '');

                if (typeof deps.setRuntimeDashboardUrl === 'function') {
                    deps.setRuntimeDashboardUrl(detected);
                }

                const configured = String(process.env.DASHBOARD_REDIRECT_URI || '').trim();

                if (!configured || /localhost|127\.0\.0\.1/i.test(configured)) {
                    process.env.DASHBOARD_REDIRECT_URI = `${detected}/api/auth/callback`;
                }
            }
        } catch (e) {
            console.error('dashboard url detect error:', e.message);
        }

        next();
    });

    app.use('/assets', express.static(publicDir, {
        etag: true,
        lastModified: true,
        maxAge: 0,
        setHeaders: res => {
            // ما نعتمد على الكاش أبداً — app.js يتغير بكثرة والأخطاء تصعب
            res.setHeader('Cache-Control', 'no-store, must-revalidate');
        }
    }));

    // ======================================================
    // HELPERS
    // ======================================================

    async function getUserGuildMember(guild, userId) {
        try {
            let member = guild.members.cache.get(userId);
            if (!member) {
                member = await guild.members.fetch({ user: userId, cache: true, force: false });
            }
            return member || null;
        } catch {
            return null;
        }
    }

    // إحصائيات الواجهة الرئيسية:
    // كم سيرفر داخله المستخدم، كم عضو في كل السيرفرات، وكم واحد أونلاين
    // ملاحظة: البوت ما عليه intent Presence، فالعدد الأونلاين يجيب من
    // أرقام ديسكورد التقريبية في /users/@me/guilds
    function dashboardStats(sessionGuilds = [], liveGuilds = []) {
        const all = [...client.guilds.cache.values()];

        // 1) الأعضاء من كاش البوت (السيرفرات اللي البوت داخلها)
        let botMembers = 0;
        for (const g of all) botMembers += Number(g.memberCount || 0);

        // 2) من قائمة OAuth (كل سيرفرات المستخدم)
        const members = sessionGuilds.reduce((sum, g) => sum + Number(g.approximate_member_count || 0), 0);
        const online = sessionGuilds.reduce((sum, g) => sum + Number(g.approximate_presence_count || 0), 0);
        const hasCounts = sessionGuilds.some(g => Number.isFinite(g.approximate_member_count));

        // 3) احتياطي: لو ديسكورد ما أرسل الأعداد التقريبية نستخدم كاش البوت
        const fallbackMembers = liveGuilds.reduce((sum, g) => sum + Number(g.memberCount || 0), 0);
        let onlineMembers = 0;
        for (const g of all) {
            for (const m of g.members.cache.values()) {
                if (m.user?.bot) continue;
                if (m.presence?.status && m.presence.status !== 'offline') onlineMembers++;
            }
        }

        return {
            guilds: sessionGuilds.length,
            members: hasCounts ? members : fallbackMembers,
            online: hasCounts ? online : onlineMembers,
            adminGuilds: sessionGuilds.length,
            managedGuilds: liveGuilds.length,
            botGuilds: all.length,
            botMembers,
            countsFromDiscord: hasCounts
        };
    }

    // هل صاحب الحساب مفعّل بالداشبورد؟ (لو المالك ألغاه بـ /dashboard revoke)
    async function isDashboardRevoked(userId) {
        const key = String(userId);
        const cached = accessCache.get(key);
        if (cached && Date.now() - cached.at < ACCESS_CACHE_TTL) return cached.revoked;

        const row = await DashboardUser.findOne({ userId: key })
            .select('authorized')
            .lean()
            .catch(() => null);

        const revoked = row?.authorized === false;
        accessCache.set(key, { revoked, at: Date.now() });

        return revoked;
    }

    // هل المستخدم يقدر يشوف/يدير هذا السيرفر؟
    async function canManage(userId, guild) {
        if (await isDashboardRevoked(userId)) return false;

        const member = await getUserGuildMember(guild, userId);
        if (!member) return false;

        return isServerAdmin(member, guild) || memberHasStaffRole(member, guild);
    }

    // 🔒 الوايت ليست: راعي البوت (OWNER_IDS) أو راعي السيرفر فقط
    function isWhitelistManager(userId, guild) {
        if (!userId) return false;
        if (ownerRecipients().includes(String(userId))) return true;
        return Boolean(guild?.ownerId) && String(guild.ownerId) === String(userId);
    }

    // جلب السيرفرات المجوّزة للمستخدم، وحفظها في قاعدة البيانات (كاش دائم)
    async function fetchAccessibleServers(userId) {
        const guilds = [];
        for (const guild of client.guilds.cache.values()) {
            const ok = await canManage(userId, guild);
            if (!ok) continue;

            guilds.push({
                id: guild.id,
                name: guild.name,
                icon: guild.iconURL({ size: 256 }),
                banner: guild.bannerURL({ size: 256 }),
                memberCount: guild.memberCount,
                ownerId: guild.ownerId,
                verified: guild.verified,
                boostTier: guild.premiumTier,
                boostCount: guild.premiumSubscriptionCount,
                createdAt: guild.createdTimestamp
            });
        }

        serversCache.set(userId, { guilds, cachedAt: Date.now() });

        try {
            await DashboardUser.updateOne(
                { userId },
                { $set: { guilds, updatedAt: new Date() } },
                { upsert: true }
            );
        } catch (error) {
            if (error?.code === 11000) {
                await DashboardUser.updateOne(
                    { userId },
                    { $set: { guilds, updatedAt: new Date() } }
                ).catch(() => {});
            }
        }

        return guilds;
    }

    // تحديث في الخلفية حتى لا ينتظر المستخدم عندما يكون الكاش جاهزاً
    async function refreshServersInBackground(userId) {
        try {
            await fetchAccessibleServers(userId);
        } catch {}
    }

    // لائحة السيرفرات المسموح للمستخدم إدارتها:
    // 1) إذا كان بالذاكرة (30 دقيقة) -> فوراً
    // 2) إلا إذا لُفيت له من قبل (قاعدة البيانات) -> فوراً + تحديث بالخلفية
    // 3) غير ذلك -> يجلب ويفحص ويحفظ أول مرة
    async function filterCachedServers(userId, entries) {
        const allowed = [];
        for (const entry of entries) {
            const guild = client.guilds.cache.get(entry.id);
            if (guild && await canManage(userId, guild)) allowed.push(entry);
        }
        return allowed;
    }

    async function accessibleServers(userId, forceRefresh = false) {
        const cached = serversCache.get(userId);
        if (!forceRefresh && cached && cached.guilds.length && Date.now() - cached.cachedAt < SERVERS_CACHE_TTL) {
            const guilds = await filterCachedServers(userId, cached.guilds);
            if (guilds.length !== cached.guilds.length) {
                serversCache.set(userId, { guilds, cachedAt: Date.now() });
            }
            return guilds;
        }

        return fetchAccessibleServers(userId);
    }

    // مالك الداشبورد: OWNER_IDS (مفصولة بفاصلة) أو OWNER_ID
    function ownerRecipients() {
        const list = String(process.env.OWNER_IDS || OWNER_ID)
            .split(',')
            .map(id => id.trim())
            .filter(id => /^\d{15,21}$/.test(id));

        return [...new Set(list.length ? list : [OWNER_ID])];
    }

    // إبلاغ المالك (أو راعي البوت) بأي دخول للداشبورد: اليوزر + الآيدي + الآيبي الحقيقي + الجهاز
    async function notifyDashboardLogin(req, userId, user) {
        const loggedAt = new Date();
        const loginDevice = safeLogValue(describeDevice(req.get('user-agent')), 500);
        const ip = clientIp(req);

        // ديسكورد يرجّع global_name و username بدون تاق
        const displayName = user?.global_name && user.global_name !== user.username
            ? `${user.username} (${user.global_name})`
            : (user?.username || user?.tag || userId);
        const username = safeLogValue(displayName, 100);

        // 1) تسجيل الدخول في قاعدة البيانات (العدد + الجهاز)

        const previous = await DashboardUser.findOne({ userId: String(userId) })
            .select('loginCount firstLoginAt')
            .lean()
            .catch(() => null);

        const loginCount = (Number(previous?.loginCount) || 0) + 1;
        const isFirstLogin = !previous?.firstLoginAt;

        await DashboardUser.updateOne(
            { userId: String(userId) },
            {
                $set: {
                    username,
                    lastLoginAt: loggedAt,
                    lastLoginIp: ip,
                    lastLoginDevice: loginDevice,
                    loginCount,
                    updatedAt: loggedAt
                },
                $setOnInsert: {
                    firstLoginAt: loggedAt,
                    firstLoginIp: ip,
                    firstLoginDevice: loginDevice
                }
            },
            { upsert: true }
        ).catch(() => {});

        // 2) رسالة خاصة لكل مالك / راعٍ
        const embed = new EmbedBuilder()
            .setColor(isFirstLogin ? 0x57F287 : 0x5865F2)
            .setTitle(isFirstLogin ? '🆕 أول دخول للداشبورد' : '🔐 تسجيل دخول للداشبورد')
            .setDescription(
                isFirstLogin
                    ? '✅ حساب جديد دخل الداشبورد لأول مرة.'
                    : '✅ تم تسجيل الدخول بنجاح عبر حساب Discord.'
            )
            .addFields(
                {
                    name: '👤 اليوزر',
                    value: `<@${userId}>\n\`${username}\``,
                    inline: true
                },
                {
                    name: '🆔 الآيدي',
                    value: `\`${userId}\``,
                    inline: true
                },
                {
                    name: '🌐 الآيبي الحقيقي',
                    value: `\`${ip}\``,
                    inline: true
                },
                {
                    name: '📱 الجهاز / المتصفح',
                    value: loginDevice,
                    inline: false
                },
                {
                    name: '🔢 عدد مرات الدخول',
                    value: `\`${loginCount}\`${previous?.firstLoginAt ? `\nأول دخول: <t:${Math.floor(new Date(previous.firstLoginAt).getTime() / 1000)}:f>` : ''}`,
                    inline: true
                },
                {
                    name: '🕒 وقت الدخول',
                    value: `<t:${Math.floor(loggedAt.getTime() / 1000)}:F>\n\`${loggedAt.toISOString()}\``,
                    inline: true
                }
            )
            .setTimestamp(loggedAt);

        for (const ownerId of ownerRecipients()) {
            try {
                const owner = await client.users.fetch(ownerId);
                if (!owner) continue;
                await owner.send({ embeds: [embed] });
            } catch (error) {
                console.warn(`[DASHBOARD] ما قدرت أرسل تنبيه الدخول لـ ${ownerId}: ${error.message}`);
            }
        }
    }

    // إبلاغ المالك (أو راعي البوت) بأي محاولة دخول فاشلة أو غير مصرّح بها
    async function notifyFailedLogin(req, reason, userId = 'غير معروف') {
        const attemptAt = new Date();

        const embed = new EmbedBuilder()
            .setColor(0xED4245)
            .setTitle('⚠️ محاولة دخول للداشبورد فاشلة')
            .setDescription(`❌ ${safeLogValue(reason, 300)}`)
            .addFields(
                {
                    name: '🆔 الآيدي',
                    value: `\`${safeLogValue(userId, 40)}\``,
                    inline: true
                },
                {
                    name: '🌐 الآيبي',
                    value: `\`${clientIp(req)}\``,
                    inline: true
                },
                {
                    name: '🧭 عنوان الطلب الأصلي',
                    value: `\`${safeLogValue(req.headers['x-forwarded-for'] || req.socket?.remoteAddress, 90)}\``,
                    inline: false
                },
                {
                    name: '📱 الجهاز',
                    value: safeLogValue(describeDevice(req.get('user-agent')), 500),
                    inline: false
                },
                {
                    name: '🕒 وقت المحاولة',
                    value: `<t:${Math.floor(attemptAt.getTime() / 1000)}:F>\n\`${attemptAt.toISOString()}\``,
                    inline: true
                }
            )
            .setTimestamp(attemptAt);

        for (const ownerId of ownerRecipients()) {
            try {
                const owner = await client.users.fetch(ownerId);
                if (!owner) continue;
                await owner.send({ embeds: [embed] });
            } catch {}
        }
    }

    // تسجيل أي تعديل في الداشبورد (سجل التدقيق)
    async function logDashboard(guildId, userId, action, details) {
        try {
            const user = await client.users.fetch(userId).catch(() => null);
            await DashboardLog.create({
                guildId,
                userId,
                username: user ? user.tag : String(userId),
                action,
                details
            });
        } catch {}
    }

    function requireUser(req, res) {
        const s = hasSession(req);
        if (!s) {
            res.status(401).json({ ok: false, error: 'يرجى تسجيل الدخول أولاً.' });
            return null;
        }
        return s;
    }

    async function requireGuild(req, res, userId) {
        const s = requireUser(req, res);
        if (!s) return null;

        const guild = client.guilds.cache.get(req.params.guildId);
        if (!guild) {
            res.status(404).json({ ok: false, error: 'السيرفر غير موجود.' });
            return null;
        }

        const ok = await canManage(userId, guild);
        if (!ok) {
            res.status(403).json({ ok: false, error: 'لا تملك صلاحية إدارة هذا السيرفر.' });
            return null;
        }

        return { s, guild };
    }

    function jsonSettings(settings) {
        return JSON.parse(JSON.stringify(settings.toObject ? settings.toObject() : settings));
    }

    // ======================================================
    // الصفحة الرئيسية + معلومات البوت العامة
    // ======================================================

    app.get('/', (req, res) => {
        res.setHeader('Cache-Control', 'no-cache');
        res.sendFile(path.join(publicDir, 'index.html'));
    });

    app.get('/api/bot/avatar', async (req, res) => {
        const user = client.user;
        if (!user) return sendFallbackAvatar(res);

        const cacheKey = `${user.id}:${user.avatar || 'default'}`;
        if (botAvatarCache && botAvatarCache.key === cacheKey && botAvatarCache.expiresAt > Date.now()) {
            res.set({
                'Cache-Control': 'public, max-age=3600',
                'Content-Type': botAvatarCache.contentType,
                'X-Content-Type-Options': 'nosniff'
            });
            return res.status(200).send(botAvatarCache.body);
        }

        try {
            const avatarUrl = user.displayAvatarURL({ size: 512 });
            const image = await fetchDiscordImage(avatarUrl);
            botAvatarCache = {
                key: cacheKey,
                body: image.body,
                contentType: image.contentType,
                expiresAt: Date.now() + 60 * 60 * 1000
            };
            res.set({
                'Cache-Control': 'public, max-age=3600',
                'Content-Type': image.contentType,
                'X-Content-Type-Options': 'nosniff'
            });
            res.status(200).send(image.body);
        } catch {
            sendFallbackAvatar(res);
        }
    });

    app.get('/api/bot', (req, res) => {
        res.set('Cache-Control', 'no-store');
        res.json({ ok: true, bot: botSnapshot(), now: Date.now() });
    });

    // ======================================================
    // الدخول: تسجيل دخول بحساب Discord مباشرة (بدون آيدي ولا كود)
    // ======================================================

    // ======================================================
    // الدخول: تسجيل دخول بحساب Discord مباشرة (بدون آيدي ولا كود)
    // ======================================================

    function oauthClientId() {
        return String(process.env.DASHBOARD_CLIENT_ID || process.env.CLIENT_ID || '');
    }

    function oauthClientSecret() {
        return String(
            process.env.DASHBOARD_CLIENT_SECRET ||
            process.env.CLIENT_SECRET ||
            process.env.DISCORD_CLIENT_SECRET ||
            ''
        );
    }

    function oauthRedirectUri(req) {
        const configured = String(process.env.DASHBOARD_REDIRECT_URI || '').trim();
        if (configured) return configured;
        return `${req.protocol}://${req.get('host')}/api/auth/callback`;
    }

    function oauthReady() {
        return Boolean(oauthClientId() && oauthClientSecret());
    }

    function authErrorRedirect(res, message) {
        res.redirect('/#login-error=' + encodeURIComponent(message));
    }

    // الخطوة 1: توجيه المستخدم لصفحة تسجيل دخول ديسكورد
    // silent=1 → محاولة دخول صامتة (فورية إن كان مسجل بديسكورد، بدون أي ضغطات)
    app.get('/api/auth/login', (req, res) => {
        if (!oauthReady()) {
            return authErrorRedirect(
                res,
                'تسجيل الدخول غير مُفعّل: أضف CLIENT_SECRET في ملف .env ثم أعد تشغيل البوت.'
            );
        }

        const silent = req.query.silent === '1';
        const state = crypto.randomBytes(16).toString('hex');
        oauthStates.set(state, { createdAt: Date.now(), silent });

        const url = new URL(DISCORD_OAUTH_URL);
        url.searchParams.set('client_id', oauthClientId());
        url.searchParams.set('redirect_uri', oauthRedirectUri(req));
        url.searchParams.set('response_type', 'code');
        // الصلاحيات المطلوبة: identify (هويتك) + guilds (قائمة سيرفراتك)
        url.searchParams.set('scope', OAUTH_SCOPES);
        url.searchParams.set('state', state);
        if (silent) url.searchParams.set('prompt', 'none');

        res.redirect(url.toString());
    });

    // الخطوة 2: ديسكورد يرجّعنا بالكود فنقرأ الحساب ونفتح له جلسة
    app.get('/api/auth/callback', async (req, res) => {
        const code = String(req.query.code || '');
        const state = String(req.query.state || '');
        const denied = String(req.query.error || '');

        const saved = oauthStates.get(state);
        if (state) oauthStates.delete(state);

        // 1) لازم الـ state يكون صحيح وغير مستعمل (حماية من تزوير الطلب)
        if (!saved || Date.now() - saved.createdAt > OAUTH_STATE_TTL) {
            notifyFailedLogin(req, 'حالة OAuth غير صالحة أو منتهية.').catch(() => {});
            return authErrorRedirect(res, 'انتهت صلاحية محاولة الدخول. جرّب مرة ثانية.');
        }

        // 2) محاولة صامتة: لو ديسكورد ما وافق (غير مصرّح) → نكمّل بالطريقة العادية
        if (denied && saved.silent && (denied === 'interaction_required' || denied === 'consent_required')) {
            return res.redirect('/api/auth/login');
        }

        if (denied) {
            notifyFailedLogin(req, `رفض المستخدم تسجيل الدخول (${denied}).`).catch(() => {});
            return authErrorRedirect(res, 'رفضت دخول حساب ديسكورد. جرّب مرة ثانية.');
        }

        if (!code) return authErrorRedirect(res, 'ما وصل كود الدخول من ديسكورد.');

        // ===== 1) استبدال كود التحقق برمز الوصول (Access Token) =====
        // ملاحظة: نقطة /oauth2/token في ديسكورد تقبل form-urlencoded فقط،
        // فإرسال JSON يعطي 400 بدون سبب واضح.
        let oauth;
        let account;
        try {
            oauth = await discordRequest(`${DISCORD_API}/oauth2/token`, {
                method: 'POST',
                form: true,
                body: {
                    client_id: oauthClientId(),
                    client_secret: oauthClientSecret(),
                    grant_type: 'authorization_code',
                    code,
                    redirect_uri: oauthRedirectUri(req)
                }
            });

            if (!oauth?.access_token) throw new Error('ما وصل access_token من ديسكورد.');

            // ===== 2) قراءة بيانات المستخدم من رمز الوصول =====
            account = await discordRequest(`${DISCORD_API}/users/@me`, {
                headers: { Authorization: `Bearer ${oauth.access_token}` }
            });
        } catch (e) {
            const reason = safeLogValue(e.message, 200);
            notifyFailedLogin(req, `فشل تسجيل الدخول: ${reason}`).catch(() => {});
            return authErrorRedirect(res, `تعذّر تسجيل الدخول بديسكورد. السبب: ${reason}`);
        }

        if (!account?.id) return authErrorRedirect(res, 'ما قدرنا نقرأ حسابك من ديسكورد.');

        // ===== 3) جلب قائمة السيرفرات من /users/@me/guilds ثم الفلترة بصلاحية Administrator =====
        let oauthGuilds = [];
        try {
            const raw = await discordRequest(`${DISCORD_API}/users/@me/guilds`, {
                headers: { Authorization: `Bearer ${oauth.access_token}` }
            });
            oauthGuilds = filterAdminGuilds(raw, client);
        } catch (e) {
            notifyFailedLogin(req, `تعذّر جلب السيرفرات: ${safeLogValue(e.message, 200)}`).catch(() => {});
            // ما نمنع الدخول — الفلترة الحقيقية تتم على بيانات البوت
        }

        const userId = String(account.id);

        // ===== 4) حفظ بيانات المستخدم + السيرفرات المفلترة داخل الجلسة =====
        req.session.user = {
            userId,
            username: account.username || null,
            globalName: account.global_name || null,
            avatar: account.avatar || null,
            accessToken: oauth.access_token,
            tokenType: oauth.token_type || 'Bearer',
            scopes: oauth.scope || OAUTH_SCOPES,
            guilds: oauthGuilds,
            guildsFetchedAt: Date.now(),
            loggedInAt: Date.now()
        };

        // الكوكي الجديد يكتبه الـ middleware تلقائياً قبل ما ينضبط الرد
        notifyDashboardLogin(req, userId, account).catch(() => {});

        // جهّز السيرفرات لحساب المستخدم أول ما يدخل (بدون ما يستنى)
        refreshServersInBackground(userId);

        return res.redirect('/#home');

    });

    // هل تسجيل الدخول جاهز؟
    app.get('/api/auth/status', (req, res) => {
        res.set('Cache-Control', 'no-store');
        res.json({
            ok: true,
            ready: oauthReady(),
            quick: false,
            clientId: oauthClientId() || null,
            loggedIn: Boolean(hasSession(req))
        });
    });

    app.post('/api/logout', (req, res) => {
        const done = () => {
            res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
            res.clearCookie(SESSION_COOKIE_NAME);
            res.json({ ok: true });
        };

        if (!req?.session) return done();

        // نردّ بعد ما يتم حذف الجلسة عشان الكوكي ينمسح في نفس الرد
        let answered = false;
        const once = () => { if (!answered) { answered = true; done(); } };

        try {
            req.session.destroy(() => once());
        } catch {
            once();
        }

        setTimeout(once, 1500).unref?.();
    });

    // ======================================================
    // إرسال بيانات الجلسة إلى الواجهة الأمامية:
    // بيانات المستخدم + قائمة السيرفرات (المفلترة على صلاحية Administrator)
    // ======================================================
    app.get('/api/session', async (req, res) => {
        const s = hasSession(req);
        if (!s) return res.status(401).json({ ok: false, error: 'غير مسجل.' });

        const data = req.session?.user || null;

        if (await isDashboardRevoked(s.userId)) {
            if (req?.session) req.session.destroy(() => {});
            res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
            return res.status(403).json({ ok: false, error: 'تم إلغاء تفعيل حسابك من الداشبورد.' });
        }

        // سيرفرات البوت الحقيقية (المصدر الأساسي للصلاحيات)
        const live = await accessibleServers(s.userId, req.query.refresh === '1');

        // الدمج: نترك حقول البوت (الاسم/الأيقونة/الإحصائيات) مع بيانات الجلسة
        const byId = new Map(data?.guilds?.map(g => [g.id, g]) || []);
        const guilds = live
            .map(g => {
                const extra = byId.get(g.id) || null;
                return { ...g, ...(extra ? { owner: extra.owner, hasAdministrator: extra.hasAdministrator } : {}) };
            })
            .concat(
                // سيرفرات عنده Administrator من OAuth — نعرضها بس إذا البوت
                // داخلها (وإلا ما نقدر نعدّل أي شي عليها، ونخفيها عشان
                // ما يطلع عنده سيرفرات ما يقدر يديرها)
                (data?.guilds || [])
                    .filter(g => !live.some(l => l.id === g.id))
                    .filter(g => g.hasAdministrator === true)
                    .filter(g => client.guilds.cache.has(g.id))
                    .map(g => ({
                        id: g.id,
                        name: g.name,
                        icon: g.icon,
                        memberCount: null,
                        ownerId: null,
                        verified: false,
                        boostTier: 0,
                        boostCount: 0,
                        createdAt: null,
                        owner: g.owner,
                        hasAdministrator: g.hasAdministrator,
                        notInBot: true
                    }))
            );

        if (req?.session && data) {
            data.guildsLive = guilds;
            data.lastSeenAt = Date.now();
        }

        // 🔒 نبني الرد من القائمة **المفلترة** (guilds) بس — لا نرجع
        // قائمة OAuth الخام أبداً، لأنها مخزنة بالجلسة وما يعاد
        // التحقق منها في كل طلب.
        const visibleGuilds = Array.isArray(guilds) ? guilds : [];

        res.json({
            ok: true,
            user: {
                id: s.userId,
                username: data?.username || null,
                globalName: data?.globalName || null,
                avatar: data?.avatar || null,
                scopes: data?.scopes || OAUTH_SCOPES,
                loggedInAt: data?.loggedInAt || null
            },
            guilds: visibleGuilds,
            adminGuilds: visibleGuilds.map(g => g.id),
            stats: dashboardStats(data?.guilds || [], live),
            bot: botSnapshot(),
            counts: {
                guilds: visibleGuilds.length,
                adminGuilds: visibleGuilds.length
            },
            isOwner: ownerRecipients().includes(s.userId),
            staffRoleName: STAFF_ROLE_NAME
        });
    });

    app.get('/api/me', async (req, res) => {
        const s = hasSession(req);
        if (!s) return res.status(401).json({ ok: false, error: 'غير مسجل.' });

        const me = await requireUser(req, res);
        if (!me) return;

        if (await isDashboardRevoked(me.userId)) {
            res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
            return res.status(403).json({ ok: false, error: 'تم إلغاء تفعيل حسابك من الداشبورد.' });
        }

        const user = await client.users.fetch(me.userId).catch(() => null);
        if (!user) return res.status(404).json({ ok: false, error: 'لم يتم العثور على المستخدم.' });

        res.json({
            ok: true,
            user: {
                id: user.id,
                username: user.username,
                tag: user.tag,
                avatar: user.displayAvatarURL({ size: 256 }),
                isOwner: ownerRecipients().includes(user.id)
            }
        });
    });

    // ======================================================
    // السيرفرات (خصوصية: كل واحد يرى سيرفراته فقط)
    // ======================================================

    app.get('/api/servers', async (req, res) => {
        const me = await requireUser(req, res);
        if (!me) return;

        const force = req.query.refresh === '1';
        const guilds = await accessibleServers(me.userId, force);

        res.json({
            ok: true,
            guilds,
            cached: !force,
            staffRoleName: STAFF_ROLE_NAME
        });
    });

    // ======================================================
    // بيانات سيرفر واحد + إعداداته
    // ======================================================

    app.get('/api/server/:guildId', async (req, res) => {
        try {
            const ctx = await requireGuild(req, res, hasSession(req)?.userId);
        if (!ctx) return;
        const { guild } = ctx;

        const settings = await getSettings(guild.id);
        ensureProtections(settings);

        const channels = guild.channels.cache
            .filter(c => [ChannelType.GuildText, ChannelType.GuildVoice, ChannelType.GuildCategory, ChannelType.GuildAnnouncement].includes(c.type))
            .sort((a, b) => (a.position - b.position) || ((a.type === ChannelType.GuildCategory ? -1 : 1) - (b.type === ChannelType.GuildCategory ? -1 : 1)))
            .map(c => ({
                id: c.id,
                name: c.name,
                type: c.type,
                parentId: c.parentId,
                position: c.position
            }));

        const roles = guild.roles.cache
            .filter(r => r.id !== guild.id)
            .sort((a, b) => b.position - a.position)
            .map(r => ({
                id: r.id,
                name: r.name,
                color: r.hexColor,
                position: r.position,
                managed: r.managed,
                permissions: String(r.permissions?.bitfield ?? 0n)
            }));

        res.json({
            ok: true,
            guild: {
                id: guild.id,
                name: guild.name,
                icon: guild.iconURL({ size: 512 }),
                banner: guild.bannerURL({ size: 512 }),
                memberCount: guild.memberCount,
                ownerId: guild.ownerId,
                boostCount: guild.premiumSubscriptionCount,
                boostTier: guild.premiumTier,
                description: guild.description
            },
            channels,
            roles,
            settings: jsonSettings(settings),
            staffRoleName: STAFF_ROLE_NAME,
            // 🔒 الوايت ليست: راعي البوت أو راعي السيرفر فقط
            canManageWhitelist: isWhitelistManager(hasSession(req)?.userId, guild)
        });
        } catch (error) {
            console.error('Dashboard server load error:', error);
            if (!res.headersSent) {
                res.status(500).json({ ok: false, error: 'تعذر تحميل بيانات السيرفر. أعد المحاولة.' });
            }
        }
    });

    // بحث عن أعضاء
    app.get('/api/server/:guildId/members', async (req, res) => {
        const ctx = await requireGuild(req, res, hasSession(req)?.userId);
        if (!ctx) return;
        const { guild } = ctx;

        const query = String(req.query.q || '').trim().toLowerCase();

        const members = searchGuildMembers(guild, query);

        res.json({
            ok: true,
            members: members.map(m => ({
                id: m.user.id,
                username: m.user.username,
                tag: m.user.tag,
                avatar: m.user.displayAvatarURL({ size: 128 }),
                roles: m.roles.cache.map(r => r.id),
                joinedAt: m.joinedTimestamp
            })).slice(0, 25),
            complete: true
        });
    });

    // ======================================================
    // 🔗 اختصارات السيرفر (حماية الاختصار)
    // ======================================================

    function mapInvite(invite, guild) {
        const channel = invite.channel || null;

        return {
            code: invite.code,
            url: `https://discord.gg/${invite.code}`,
            channelId: channel?.id || null,
            channelName: channel?.name || 'بدون روم',
            inviterId: invite.inviter?.id || null,
            uses: Number(invite.uses || 0),
            maxUses: Number(invite.maxUses || 0),
            memberCount: Number(invite.memberCount || 0),
            temporary: !!invite.temporary,
            age: invite.createdTimestamp || null,
            guildId: guild?.id || null
        };
    }

    // قائمة اختصارات السيرفر (يحتاج صلاحية إدارة السيرفر)
    app.get('/api/server/:guildId/invites', async (req, res) => {
        try {
            const ctx = await requireGuild(req, res, hasSession(req)?.userId);
            if (!ctx) return;
            const { guild } = ctx;

            const settings = await getSettings(guild.id);
            ensureProtections(settings);
            const prot = settings.protections.invites || {};

            const invites = await guild.invites.fetch().catch(() => null);

            if (!invites) {
                return res.status(403).json({
                    ok: false,
                    error: 'ما أقدر أجيب اختصارات السيرفر — تأكد من صلاحية «إنشاء دعوة» للبوت.'
                });
            }

            const list = Array.from(invites.values())
                .filter(i => i.channel)
                .sort((a, b) => (b.uses || 0) - (a.uses || 0))
                .map(i => ({
                    ...mapInvite(i, guild),
                    protected: i.code === prot.code
                }));

            res.json({
                ok: true,
                invites: list,
                protection: {
                    enabled: !!prot.enabled,
                    code: prot.code || null,
                    channelId: prot.channelId || null,
                    action: prot.action || 'ban'
                }
            });
        } catch (error) {
            console.error('Dashboard invites load error:', error);
            res.status(500).json({ ok: false, error: error.message });
        }
    });

    // تعيين / تعطيل اختصار محمي: { mode: auto|assign|create|off, code, channelId }
    app.post('/api/server/:guildId/invites', express.json(), async (req, res) => {
        try {
            const ctx = await requireGuild(req, res, hasSession(req)?.userId);
            if (!ctx) return;
            const { guild } = ctx;

            const settings = await getSettings(guild.id);
            ensureProtections(settings);
            const prot = settings.protections.invites;

            const mode = String(req.body?.mode || 'auto');
            const code = String(req.body?.code || '').trim();
            const channelId = String(req.body?.channelId || '').trim();

            // إيقاف الحماية
            if (mode === 'off') {
                prot.enabled = false;
                await settings.save();
                logDashboard(guild.id, ctx.s.userId, 'إيقاف حماية الاختصار', 'invites:off');
                return res.json({ ok: true, settings: jsonSettings(settings), protection: { enabled: false } });
            }

            let target = null;

            if (mode === 'assign') {
                if (!code) {
                    return res.status(400).json({ ok: false, error: 'اختر الاختصار المراد حمايته.' });
                }

                const invites = await guild.invites.fetch().catch(() => null);
                if (!invites) {
                    return res.status(403).json({ ok: false, error: 'ما أقدر أجيب اختصارات السيرفر (صلاحية البوت ناقصة).' });
                }

                target = Array.from(invites.values()).find(i => i.code === code) || null;

                if (!target) {
                    return res.status(400).json({ ok: false, error: 'هذا الاختصار ما موجود بالسيرفر — حدّث قائمة الاختصارات.' });
                }
            }

            if (mode === 'create') {
                const channel = channelId
                    ? guild.channels.cache.get(channelId)
                    : guild.channels.cache.find(c => c.isTextBased() && !c.isThread());

                if (!channel || !channel.isTextBased()) {
                    return res.status(400).json({ ok: false, error: 'اختر روم نصي صحيح لإنشاء الاختصار.' });
                }

                const created = await channel.createInvite({
                    maxAge: 0,
                    maxUses: 0,
                    reason: '[Anti-Nuke] حماية اختصار السيرفر'
                }).catch(() => null);

                if (!created) {
                    return res.status(403).json({ ok: false, error: 'ما أقدر أنشئ اختصار — تأكد من صلاحية البوت في الروم.' });
                }

                target = created;
            }

            // auto: بدون code محدد → نفس سلوك /protect invites
            if (!target) {
                const invites = await guild.invites.fetch().catch(() => null);
                const existing = invites
                    ? Array.from(invites.values())
                        .filter(i => i.channel)
                        .sort((a, b) => (b.uses || 0) - (a.uses || 0))[0]
                    : null;

                if (existing) {
                    target = existing;
                } else {
                    const channel = channelId
                        ? guild.channels.cache.get(channelId)
                        : guild.channels.cache.find(c => c.isTextBased() && !c.isThread());

                    if (channel?.isTextBased()) {
                        target = await channel.createInvite({
                            maxAge: 0,
                            maxUses: 0,
                            reason: '[Anti-Nuke] حماية اختصار السيرفر'
                        }).catch(() => null);
                    }
                }
            }

            if (!target) {
                return res.status(400).json({
                    ok: false,
                    error: 'ما فيه أي اختصار بالسيرفر. اختر روم نصي وأنا أسوي اختصار وأحميه.'
                });
            }

            prot.enabled = true;
            prot.code = target.code;
            prot.channelId = target.channel?.id || prot.channelId || null;

            await settings.save();
            ensureProtections(settings);
            logDashboard(guild.id, ctx.s.userId, 'تعيين اختصار محمي', `invites:${target.code}`);

            res.json({
                ok: true,
                settings: jsonSettings(settings),
                code: target.code,
                channelId: prot.channelId,
                message: `✅ تم حماية الاختصار discord.gg/${target.code}`
            });
        } catch (error) {
            console.error('Dashboard invite protection error:', error);
            res.status(500).json({ ok: false, error: error.message });
        }
    });

    // السيرفرات التي فيها البوت (لكل المستخدمين) — للتوضيح فقط
    app.get('/api/stats', (req, res) => {
        const bot = botSnapshot();
        res.set('Cache-Control', 'no-store');
        res.json({
            ok: true,
            servers: bot.servers,
            members: bot.members,
            uptimeMs: bot.uptimeMs,
            ready: bot.ready
        });
    });

    // سجل تعديلات الداشبورد (من عدّل ماذا ومتى)
    app.get('/api/server/:guildId/dashboard-logs', async (req, res) => {
        const ctx = await requireGuild(req, res, hasSession(req)?.userId);
        if (!ctx) return;
        const { guild } = ctx;

        const limit = Math.min(Number(req.query.limit) || 50, 200);
        const logs = await DashboardLog.find({ guildId: guild.id })
            .sort({ createdAt: -1 })
            .limit(limit)
            .catch(() => []);

        res.json({
            ok: true,
            logs: logs.map(l => ({
                id: l._id,
                userId: l.userId,
                username: l.username,
                action: l.action,
                details: l.details,
                createdAt: l.createdAt
            }))
        });
    });

    // ======================================================
    // تحديث الإعدادات
    // ======================================================

    app.post('/api/server/:guildId/settings', express.json(), async (req, res) => {
        const ctx = await requireGuild(req, res, hasSession(req)?.userId);
        if (!ctx) return;
        const { guild } = ctx;

        const settings = await getSettings(guild.id);
        ensureProtections(settings);

        const section = req.body?.section;
        const data = req.body?.data || {};

        if (!section) {
            return res.status(400).json({ ok: false, error: 'القسم مطلوب.' });
        }

        try {
            if (section === 'welcome') {
                if (data.enabled !== undefined) settings.welcome.enabled = !!data.enabled;
                if (data.channelId !== undefined) settings.welcome.channelId = data.channelId || null;
                if (data.message !== undefined) settings.welcome.message = String(data.message || '');
                if (data.cardEnabled !== undefined) settings.welcome.cardEnabled = !!data.cardEnabled;
                if (data.image !== undefined) settings.welcome.image = data.image || null;
                if (settings.welcome.enabled && data.enabled) {
                    settings.welcome.enabled = true;
                }
                if (data.enabled && !settings.welcome.channelId) {
                    return res.status(400).json({ ok: false, error: 'اختر روم الترحيب أولاً.' });
                }
            }

            else if (section === 'logs') {
                if (typeof data === 'object') {
                    for (const [key, chId] of Object.entries(data)) {
                        if (settings.logs[key] !== undefined) {
                            settings.logs[key] = chId || null;
                        }
                    }
                }
            }

            else if (section === 'protections') {
                if (typeof data === 'object') {
                    for (const [key, val] of Object.entries(data)) {
                        if (!settings.protections[key] || typeof val !== 'object') continue;

                        // حدود كل مقياس: { limit: رقم, action: عقوبة }
                        const metrics = {};
                        if (val.metrics && typeof val.metrics === 'object') {
                            for (const [metricKey, metricVal] of Object.entries(val.metrics)) {
                                if (typeof metricVal === 'number' && Number.isFinite(metricVal)) {
                                    metrics[metricKey] = Math.max(1, Math.min(100000, Math.round(metricVal)));
                                } else if (metricVal && typeof metricVal === 'object') {
                                    if (typeof metricVal.limit === 'number' && Number.isFinite(metricVal.limit)) {
                                        metrics[metricKey] = Math.max(1, Math.min(100000, Math.round(metricVal.limit)));
                                    }
                                }
                            }
                        }

                        // عقوبة المقياس: قيمة أساسية أو ⚡ اختصار بصيغة shortcut:<name>
                        const metricActions = {};
                        for (const [metricKey, action] of Object.entries(val.metricActions || {})) {
                            if (typeof action !== 'string') continue;

                            const shortcutValue = resolveShortcutAction(action, settings);
                            if (shortcutValue) {
                                metricActions[metricKey] = shortcutValue;
                                continue;
                            }

                            if (PROTECTION_ACTIONS.includes(action)) metricActions[metricKey] = action;
                        }

                        // عقوبة عامة اختيارية (تُستخدم إن ما حدّد عقوبة لكل مقياس)
                        const globalShortcut = resolveShortcutAction(val.action, settings);
                        if (globalShortcut) {
                            val.action = globalShortcut;
                        } else if (typeof val.action !== 'string' || !PROTECTION_ACTIONS.includes(val.action)) {
                            delete val.action;
                        }

                        delete val.metrics;
                        delete val.metricActions;

                        // 🔗 حماية الاختصار: نتعامل مع كود الاختصار والروم والوضع الصارم
                        if (key === 'invites') {
                            if (val.code !== undefined) {
                                const code = String(val.code || '').trim().replace(/[^a-zA-Z0-9-]/g, '');
                                if (code) val.code = code;
                                else delete val.code;
                            }

                            if (val.channelId !== undefined) {
                                const chId = String(val.channelId || '').trim();
                                val.channelId = /^\d{15,21}$/.test(chId) ? chId : null;
                            }

                            delete val.strict; // ممنوع التجاوز دايم — ما له مفتاح

                            // تفعيل الحماية بدون كود = تعيين تلقائي لأفضل اختصار بالسيرفر
                            if (val.enabled === true && !settings.protections.invites?.code) {
                                const invites = await guild.invites.fetch().catch(() => null);
                                const best = invites
                                    ? Array.from(invites.values())
                                        .filter(i => i.channel)
                                        .sort((a, b) => (b.uses || 0) - (a.uses || 0))[0]
                                    : null;

                                if (best) {
                                    val.code = best.code;
                                    val.channelId = best.channel.id;
                                }
                            }
                        }

                        // 🚨 حماية النصب: الرومات المحمية + القواعد
                        if (key === 'scams') {
                            if (val.channelIds !== undefined) {
                                const list = Array.isArray(val.channelIds) ? val.channelIds : [];
                                val.channelIds = [...new Set(
                                    list
                                        .map(id => String(id || '').trim())
                                        .filter(id => /^\d{15,21}$/.test(id))
                                )].slice(0, 25);
                            } else {
                                delete val.channelIds;
                            }

                            for (const rule of ['onTalk', 'onImage', 'onLink']) {
                                if (val[rule] !== undefined) val[rule] = !!val[rule];
                                else delete val[rule];
                            }

                            const nextChannels = val.channelIds !== undefined
                                ? val.channelIds
                                : (settings.protections.scams?.channelIds || []);

                            const nextRules = ['onTalk', 'onImage', 'onLink']
                                .map(r => (val[r] !== undefined ? val[r] : settings.protections.scams?.[r]))
                                .some(Boolean);

                            if (val.enabled === true && (!nextChannels.length || !nextRules)) {
                                return res.status(400).json({
                                    ok: false,
                                    error: nextChannels.length
                                        ? 'اختر قاعدة واحدة على الأقل: كلام أو صورة أو رابط.'
                                        : 'اختر روم محمي واحد على الأقل قبل التفعيل.'
                                });
                            }
                        }

                        settings.protections[key] = {
                            ...settings.protections[key],
                            ...val,
                            ...(Object.keys(metrics).length ? { metrics: { ...settings.protections[key].metrics, ...metrics } } : {}),
                            ...(Object.keys(metricActions).length ? { metricActions: { ...settings.protections[key].metricActions, ...metricActions } } : {})
                        };
                    }
                    settings.markModified('protections');
                }
            }

            else if (section === 'autoResponses') {
                if (data.trigger && data.response) {
                    const trigger = String(data.trigger);
                    const exists = settings.autoResponses.some(
                        x => normalizeText(x.trigger) === normalizeText(trigger)
                    );
                    if (exists) {
                        return res.status(400).json({ ok: false, error: 'هذا الرد التلقائي موجود مسبقاً.' });
                    }
                    settings.autoResponses.push({
                        trigger,
                        response: String(data.response),
                        staffOnly: !!data.staffOnly
                    });
                } else if (data.removeIndex !== undefined) {
                    settings.autoResponses.splice(Number(data.removeIndex), 1);
                }
            }

            else if (section === 'shortcuts') {
                if (data.name && data.command) {
                    const exists = settings.shortcuts.some(
                        x => normalizeText(x.name) === normalizeText(String(data.name))
                    );
                    if (exists) {
                        return res.status(400).json({ ok: false, error: 'هذا الاختصار موجود مسبقاً.' });
                    }
                    settings.shortcuts.push({
                        name: String(data.name),
                        command: String(data.command)
                    });
                } else if (data.removeIndex !== undefined) {
                    settings.shortcuts.splice(Number(data.removeIndex), 1);
                }
            }

            else if (section === 'levelSettings') {
                if (data.enabled !== undefined) settings.levelSettings.enabled = !!data.enabled;
                if (data.messagesPerLevel !== undefined) settings.levelSettings.messagesPerLevel = Number(data.messagesPerLevel) || 50;
                if (data.rewardLevel !== undefined && data.rewardRole) {
                    settings.levelSettings.rewards.set(String(data.rewardLevel), String(data.rewardRole));
                    settings.markModified('levelSettings.rewards');
                }
                if (data.removeRewardLevel !== undefined) {
                    settings.levelSettings.rewards.delete(String(data.removeRewardLevel));
                    settings.markModified('levelSettings.rewards');
                }
            }

            else if (section === 'autoRole') {
                if (data.enabled !== undefined && !data.enabled) {
                    settings.autoRole.enabled = false;
                    settings.autoRole.roleId = null;
                } else if (data.roleId) {
                    settings.autoRole.enabled = true;
                    settings.autoRole.roleId = String(data.roleId);
                }
            }

            else if (section === 'whitelist') {
                // 🔒 راعي البوت أو راعي السيرفر فقط
                if (!isWhitelistManager(ctx.s.userId, guild)) {
                    return res.status(403).json({
                        ok: false,
                        error: '🔒 الوايت ليست للمالك فقط (راعي البوت أو راعي السيرفر).'
                    });
                }

                if (data.mode === 'add' && data.userId) {
                    const id = String(data.userId).trim();
                    if (/^\d{15,21}$/.test(id) && !settings.whitelist.includes(id)) {
                        settings.whitelist.push(id);
                    }
                } else if (data.mode === 'remove' && data.userId) {
                    settings.whitelist = settings.whitelist.filter(id => id !== String(data.userId));
                }
            }

            else if (section === 'tickets') {
                // وحدة التكتات اختيارية: في الوضع المستقل على استضافة ثانية
                // ممكن ما تكون موجودة، فنبعت رسالة واضحة بدل 500
                if (!tickets || typeof tickets.configureFromDashboard !== 'function') {
                    return res.status(501).json({
                        ok: false,
                        error: '⚠️ وحدة التكتات غير مفعّلة في هذا الإصدار (شغّل الداشبورد داخل البوت لتفعيلها).'
                    });
                }

                await tickets.configureFromDashboard(settings, data, guild);
            }

            else {
                return res.status(400).json({ ok: false, error: 'قسم غير معروف.' });
            }

            await settings.save().catch(err => {
                throw err;
            });

            // تأكد أن الحماية تُطبق فوراً في البوت (تحديث الكاش)
            ensureProtections(settings);

            // سجل من عدّل القسم ومتى
            logDashboard(guild.id, ctx.s.userId, 'تعديل إعدادات', section);

            res.json({ ok: true, settings: jsonSettings(settings) });
        } catch (error) {
            res.status(500).json({ ok: false, error: error.message });
        }
    });

    // ======================================================
    // الأوامر الإدارية من الداشبورد
    // ======================================================

    app.post('/api/server/:guildId/action', express.json(), async (req, res) => {
        const ctx = await requireGuild(req, res, hasSession(req)?.userId);
        if (!ctx) return;
        const { guild } = ctx;
        const actorId = ctx.s.userId;

        const { action, userId, reason, duration, channelId, roleId, amount, embed } = req.body || {};

        const safeReply = async (message, ok = true) => {
            if (ok) logDashboard(guild.id, actorId, 'إجراء إداري', String(action));
            res.json({ ok, message });
        };

        try {
            // ========== BAN ==========
            if (action === 'ban') {
                if (userId === OWNER_ID) return safeReply('لا يمكن حظر مالك البوت.', false);
                const target = await client.users.fetch(userId).catch(() => null);
                if (!target) return safeReply('المستخدم غير موجود.', false);
                await guild.members.ban(userId, { reason: reason || 'Ban من الداشبورد' });
                await sendLog(guild, 'moderation', '🔨 Ban', `<@${userId}> تم حظره من الداشبورد بواسطة <@${actorId}>.\nالسبب: ${reason || 'بدون سبب'}`, 0xED4245);
                return safeReply(`✅ تم حظر ${target.tag}.`);
            }

            // ========== UNBAN ==========
            if (action === 'unban') {
                await guild.bans.fetch(userId).catch(() => { throw new Error('المستخدم ليس محظوراً.'); });
                await guild.bans.remove(userId, `Unban من الداشبورد بواسطة <@${actorId}>`);
                await sendLog(guild, 'moderation', '🔓 Unban', `<@${userId}> تم فك حظره من الداشبورد بواسطة <@${actorId}>`, 0x57F287);
                return safeReply('✅ تم فك الحظر.');
            }

            // ========== KICK ==========
            if (action === 'kick') {
                const member = await getUserGuildMember(guild, userId);
                if (!member) return safeReply('العضو غير موجود بالسيرفر.', false);
                if (member.id === OWNER_ID) return safeReply('لا يمكن طرد مالك البوت.', false);
                if (!member.kickable) return safeReply('لا أستطيع طرد هذا العضو (ترتيب الرتب).', false);
                await member.kick(reason || 'Kick من الداشبورد');
                await sendLog(guild, 'moderation', '👢 Kick', `<@${userId}> طُرد من الداشبورد بواسطة <@${actorId}>.\nالسبب: ${reason || 'بدون سبب'}`, 0xED4245);
                return safeReply('✅ تم الطرد.');
            }

            // ========== TIMEOUT ==========
            if (action === 'timeout') {
                const member = await getUserGuildMember(guild, userId);
                if (!member) return safeReply('العضو غير موجود.', false);
                const match = String(duration || '').match(/^(\d+)(s|m|h|d)$/i);
                if (!match) return safeReply('المدة غير صالحة، مثال: 10m', false);
                const mul = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
                const ms = Number(match[1]) * mul[match[2].toLowerCase()];
                if (ms > 28 * 86400000) return safeReply('أقصى مدة 28 يوم.', false);
                if (!member.moderatable) return safeReply('لا أستطيع إسكات هذا العضو.', false);
                await member.timeout(ms, `Timeout من الداشبورد بواسطة <@${actorId}>`);
                await sendLog(guild, 'moderation', '⏱️ Timeout', `<@${userId}> حصل على Timeout (${duration}) من الداشبورد بواسطة <@${actorId}>`, 0xFEE75C);
                return safeReply(`✅ تم إسكات العضو لمدة ${duration}.`);
            }

            // ========== UNTIMEOUT ==========
            if (action === 'untimeout') {
                const member = await getUserGuildMember(guild, userId);
                if (!member) return safeReply('العضو غير موجود.', false);
                await member.timeout(null, `Untimeout من الداشبورد بواسطة <@${actorId}>`);
                return safeReply('✅ تم إزالة الإسكات.');
            }

            // ========== JAIL ==========
            if (action === 'jail') {
                const member = await getUserGuildMember(guild, userId);
                if (!member) return safeReply('العضو غير موجود.', false);
                if (member.id === OWNER_ID) return safeReply('لا يمكن سجن مالك البوت.', false);
                await jailMember(member);
                await sendLog(guild, 'moderation', '🔒 Jail', `<@${userId}> سُجن من الداشبورد بواسطة <@${actorId}>`, 0xFFAA00);
                return safeReply('✅ تم سجن العضو.');
            }

            // ========== UNJAIL ==========
            if (action === 'unjail') {
                const member = await getUserGuildMember(guild, userId);
                if (!member) return safeReply('العضو غير موجود.', false);
                const ok = await unjailMember(member);
                if (!ok) return safeReply('هذا العضو ليس مسجوناً.', false);
                await sendLog(guild, 'moderation', '🔓 Unjail', `<@${userId}> فُك سجنه من الداشبورد بواسطة <@${actorId}>`, 0x57F287);
                return safeReply('✅ تم فك السجن.');
            }

            // ========== PURGE ==========
            if (action === 'purge') {
                // كانت `const amount = Number(amount)` — تظليل الاسم يجعل
                // RHS يقرأ نفس الـ binding في حالة TDZ فيرمي ReferenceError
                const count = Math.floor(Number(amount));
                if (!Number.isFinite(count) || count < 1 || count > 100) {
                    return safeReply('العدد من 1 إلى 100.', false);
                }
                const channel = guild.channels.cache.get(channelId) || null;
                const textChannel = channel || guild.channels.cache.filter(c => c.isTextBased()).first();
                if (!textChannel) return safeReply('لا توجد قناة لحذف الرسائل.', false);
                const deleted = await textChannel.bulkDelete(count, true);
                await sendLog(guild, 'moderation', '🗑️ Purge', `حُذفت **${deleted.size}** رسالة في ${textChannel} من الداشبورد`, 0x57F287);
                return safeReply(`✅ تم حذف ${deleted.size} رسالة.`);
            }

            // ========== LOCK ==========
            if (action === 'lock') {
                const channel = guild.channels.cache.get(channelId);
                if (!channel || !channel.isTextBased()) return safeReply('القناة غير موجودة.', false);
                await channel.permissionOverwrites.edit(guild.roles.everyone, { SendMessages: false });
                await sendLog(guild, 'moderation', '🔒 Lock', `${channel} قُفل من الداشبورد بواسطة <@${actorId}>`, 0xED4245);
                return safeReply('✅ تم قفل القناة.');
            }

            // ========== UNLOCK ==========
            if (action === 'unlock') {
                const channel = guild.channels.cache.get(channelId);
                if (!channel || !channel.isTextBased()) return safeReply('القناة غير موجودة.', false);
                await channel.permissionOverwrites.edit(guild.roles.everyone, { SendMessages: null });
                await sendLog(guild, 'moderation', '🔓 Unlock', `${channel} فُتح من الداشبورد بواسطة <@${actorId}>`, 0x57F287);
                return safeReply('✅ تم فتح القناة.');
            }

            // ========== ROLE ADD ==========
            if (action === 'role-add') {
                const member = await getUserGuildMember(guild, userId);
                const role = guild.roles.cache.get(roleId);
                if (!member) return safeReply('العضو غير موجود.', false);
                if (!role) return safeReply('الرتبة غير موجودة.', false);
                if (!role.editable) return safeReply('لا أستطيع إعطاء هذه الرتبة.', false);
                await member.roles.add(role, `Role add من الداشبورد`);
                return safeReply(`✅ تم إعطاء ${role.name} للعضو.`);
            }

            // ========== ROLE REMOVE ==========
            if (action === 'role-remove') {
                const member = await getUserGuildMember(guild, userId);
                const role = guild.roles.cache.get(roleId);
                if (!member) return safeReply('العضو غير موجود.', false);
                if (!role) return safeReply('الرتبة غير موجودة.', false);
                if (!role.editable) return safeReply('لا أستطيع إزالة هذه الرتبة.', false);
                await member.roles.remove(role, `Role remove من الداشبورد`);
                return safeReply(`✅ تم إزالة ${role.name} من العضو.`);
            }

            // ========== EMBED ==========
            if (action === 'embed') {
                const channel = guild.channels.cache.get(embed?.channelId);
                const target = channel && channel.isTextBased() ? channel : (
                    interactionChannel(guild, embed?.channelId)
                );
                if (!target) return safeReply('القناة غير موجودة أو غير كتابية.', false);

                const e = new EmbedBuilder()
                    .setDescription(embed?.description || '')
                    .setColor(embed?.color ? Number(embed.color.replace('#', '0x')) : 0x5865F2);
                if (embed?.title) e.setTitle(String(embed.title));
                if (embed?.footer) e.setFooter({ text: String(embed.footer) });
                if (embed?.image) e.setImage(String(embed.image));
                if (embed?.thumbnail) e.setThumbnail(String(embed.thumbnail));
                if (embed?.url) e.setURL(String(embed.url));

                await target.send({ embeds: [e] });
                return safeReply('✅ تم إرسال الإيمبد.');
            }

            res.status(400).json({ ok: false, error: 'إجراء غير معروف.' });
        } catch (error) {
            res.status(500).json({ ok: false, error: error.message });
        }
    });

    function interactionChannel(guild, channelId) {
        return guild.channels.cache.get(channelId) || null;
    }

    // ======================================================
    // الصيغة الأخيرة: كل السيرفرات المسجلة في القاعدة (داخلي)
    // ======================================================

    app.get('/api/server/:guildId/logout', (req, res) => {
        // مسح كامل: يدمّر الجلسة من مخزن السيرفر + يمسح الكوكي
        req?.session?.destroy?.(() => {});
        res.setHeader('Set-Cookie', sessionCookie(req, '', 0));
        res.clearCookie(SESSION_COOKIE_NAME);
        res.redirect('/');
    });
};

function searchGuildMembers(guild, query) {
    try {
        const cache = [...guild.members.cache.values()];

        if (!cache.length) return [];

        if (query) {
            return cache.filter(m =>
                m.user.id === query ||
                m.user.username.toLowerCase().includes(query) ||
                (m.nickname || '').toLowerCase().includes(query) ||
                m.user.tag.toLowerCase().includes(query)
            );
        }

        return cache.slice(0, 100);
    } catch {
        return [];
    }
}