'use strict';
// ======================================================
// شكل الحمايات والمقاييس — نسخة الداشبورد
// ======================================================
// مولّد تلقائياً من index.js (نسخة حرفية) — لا تعدّله يدوي.
//   node tools/sync-panel-lib.js

const DEFAULT_PROTECTIONS = {
    channels: { enabled: true, limit: 5, action: 'ban' },
    roles: { enabled: true, limit: 5, action: 'ban' },
    bans: { enabled: true, limit: 3, action: 'kick' },
    bots: { enabled: true },
    spam: { enabled: true, limit: 5, timeframe: 5000, maxLength: 400, repeatedChar: 8, action: 'timeout' },
    webhooks: { enabled: true, limit: 5, action: 'ban' },
    invites: { enabled: false, code: null, channelId: null, action: 'ban' },
    scams: { enabled: false, channelIds: [], action: 'ban' }
};

// ======================================================
// مقاييس الحماية — كل حماية لها خيارات يحدد صاحب السيرفر
// حدّها بنفسه (عدد المحاولات / الإنشاء / الحذف / التعديل...)
// ======================================================

const PROTECTION_ACTIONS = [
    { name: '🔨 Ban', value: 'ban' },
    { name: '👢 Kick', value: 'kick' },
    { name: '🔇 Time-out (10 دقائق)', value: 'timeout' },
    { name: '🔒 Jail (سجن — ما يشوف ولا روم)', value: 'jail' },
    { name: '🎭 إزالة كل الرتب', value: 'removeroles' }
];

const PROTECTION_METRICS = {
    channels: [
        { key: 'create', label: 'عدد مرات إنشاء الرومات', def: 5, min: 1, max: 1000 },
        { key: 'delete', label: 'عدد مرات حذف الرومات', def: 5, min: 1, max: 1000 },
        { key: 'update', label: 'عدد مرات تعديل الرومات', def: 20, min: 1, max: 1000 }
    ],
    roles: [
        { key: 'create', label: 'عدد مرات إنشاء الرتب', def: 5, min: 1, max: 1000 },
        { key: 'delete', label: 'عدد مرات حذف الرتب', def: 5, min: 1, max: 1000 },
        { key: 'update', label: 'عدد مرات تعديل الرتب', def: 20, min: 1, max: 1000 }
    ],
    bans: [
        { key: 'count', label: 'عدد عمليات الحظر المسموحة', def: 3, min: 1, max: 1000 }
    ],
    bots: [
        { key: 'joins', label: 'عدد البوتات المنضمة المسموح', def: 3, min: 1, max: 1000 }
    ],
    spam: [
        { key: 'messages', label: 'عدد الرسائل المسموحة قبل السبام', def: 5, min: 1, max: 1000 },
        { key: 'length', label: 'أقصى طول للرسالة (حرف)', def: 400, min: 1, max: 4000 },
        { key: 'repeat', label: 'عدد تكرار الحرف (يُعتبر سبام)', def: 8, min: 1, max: 1000 },
        { key: 'fontsize', label: 'عدد تكرار حرف عريض (تكبير الخط)', def: 8, min: 1, max: 1000 }
    ],
    webhooks: [
        { key: 'create', label: 'عدد مرات إنشاء ويب هوك', def: 5, min: 1, max: 1000 },
        { key: 'delete', label: 'عدد مرات حذف ويب هوك', def: 5, min: 1, max: 1000 }
    ],
    invites: [
        { key: 'redirect', label: 'عدد مرات إعادة توجيه اختصار السيرفر', def: 1, min: 1, max: 1000 }
    ],
    scams: [
        { key: 'talk', label: 'عدد الرسائل المسموحة في الروم', def: 1, min: 1, max: 100 },
        { key: 'image', label: 'عدد الصور/الملفات المرئية المسموحة', def: 1, min: 1, max: 100 },
        { key: 'links', label: 'عدد الروابط المسموحة', def: 1, min: 1, max: 100 }
    ]
};

// كل المقاييس المعرّفة لـنوع حماية
function metricsFor(typeKey) {
    return PROTECTION_METRICS[typeKey] || [];
}

function metricDef(typeKey, metricKey) {
    return metricsFor(typeKey).find(m => m.key === metricKey) || null;
}

// يقرأ حدّ المقياس الذي حدده صاحب السيرفر (وإلا يرجع الافتراضي)
function metricLimit(prot, typeKey, metricKey, fallback) {
    const def = metricDef(typeKey, metricKey);
    const stored = prot?.metrics ? prot.metrics[metricKey] : undefined;
    const value = Number(stored);

    if (Number.isFinite(value) && value >= 0) return value;
    if (def) return def.def;
    return fallback;
}

// يقرأ عقوبة المقياس (وإلا يرجع عقوبة الحماية العامة)
function metricAction(prot, typeKey, metricKey, fallback = 'ban') {
    const stored = prot?.metricActions ? prot.metricActions[metricKey] : undefined;
    const allowed = PROTECTION_ACTIONS.map(a => a.value);

    // ⚡ اختصار مخصص: shortcut:<اسم الاختصار>
    const isShortcut = v => typeof v === 'string' && v.startsWith('shortcut:') && v.slice(9).trim().length > 0;
    if (isShortcut(stored)) return stored;
    if (typeof stored === 'string' && allowed.includes(stored)) return stored;
    if (isShortcut(prot?.action)) return prot.action;
    if (prot?.action && allowed.includes(prot.action)) return prot.action;

    return allowed.includes(fallback) ? fallback : 'ban';
}

// يضمن وجود خريطة المقاييس في الإعدادات القديمة
function ensureMetricMaps(protections) {
    let anyChanged = false;

    for (const typeKey of Object.keys(PROTECTION_METRICS)) {
        const prot = protections?.[typeKey];
        if (!prot) continue;

        let changed = false;

        if (!prot.metrics || typeof prot.metrics !== 'object' || Array.isArray(prot.metrics)) {
            prot.metrics = {};
            changed = true;
        }

        if (!prot.metricActions || typeof prot.metricActions !== 'object' || Array.isArray(prot.metricActions)) {
            prot.metricActions = {};
            changed = true;
        }

        for (const m of PROTECTION_METRICS[typeKey]) {
            if (prot.metrics[m.key] === undefined) {
                prot.metrics[m.key] = m.def;
                changed = true;
            }

            if (!prot.metricActions[m.key]) {
                prot.metricActions[m.key] = prot.action || 'ban';
                changed = true;
            }
        }

        if (changed) anyChanged = true;
    }

    return anyChanged;
}
module.exports = {
    DEFAULT_PROTECTIONS,
    PROTECTION_ACTIONS,
    PROTECTION_METRICS,
    metricsFor,
    metricDef,
    metricLimit,
    metricAction,
    ensureMetricMaps
};
