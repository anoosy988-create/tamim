'use strict';
// ======================================================
// تشغيل الداشبورد على استضافة ثانية (Standalone)
// ======================================================
// الاستخدام:
//   cp .env.example .env      ثم املأ القيم
//   node standalone.js
//
// كل شي يجي من .env:
//   DISCORD_TOKEN   توكن البوت (لازم يكون توكنك أنت — انظر التحذير بالأسفل)
//   OWNER_IDS       ايدي المالك/الستريتر (مفصولة بفاصلة)
//   MONGO_URI       نفس قاعدة بيانات البوت
//   CLIENT_ID / CLIENT_SECRET / DASHBOARD_REDIRECT_URI / SESSION_SECRET / DASHBOARD_URL
//
// ⚠️  توكن ديسكورد ما يقدر يتصل من جهازين بنفس الوقت.
//     إذا البوت شغّال على استضافة أول وتبي الداشبورد على ثانية،
//     لازم تعطي الداشبورد توكن بوت ثاني (تطبيق Discord جديد) وإلا
//     الـ gateway بيزيح البوت من الاتصال. يبقى البوت شغّال؟ لا، يقلع.

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');

const ctx = require('./lib/bot-context.js');
const setupDashboard = require('./server.js');

const PORT = Number(process.env.PORT) || 10000;

// ======================================================
// 1) تحقق مبكر — نقول بالضبط وش ناقص بدل ما يطلع error غامض
// ======================================================

const required = [
    ['DISCORD_TOKEN', 'توكن البوت'],
    ['MONGO_URI', 'رابط MongoDB'],
    ['CLIENT_ID', 'Client ID من Discord Developer Portal'],
    ['CLIENT_SECRET', 'Client Secret من Discord Developer Portal'],
    ['OWNER_IDS', 'ايدي المالك (مفصولة بفاصلة)']
];

const missing = required.filter(([key]) => !process.env[key]);

if (missing.length) {
    console.error('\n============================================');
    console.error('  ❌ الداشبورد المستقل ناقصه متغيرات بيئة');
    console.error('============================================');
    for (const [key, label] of missing) {
        console.error(`  - ${key}  (${label})`);
    }
    console.error('\n  انسخ .env.example إلى .env واملأ القيّم.');
    console.error('============================================\n');
    process.exit(1);
}

// ======================================================
// 2) قاعدة البيانات
// ======================================================

async function connectDb() {
    const uri = process.env.MONGO_URI;
    const name = (process.env.MONGO_DB || 'cypher').replace(/[^a-zA-Z0-9_-]/g, '');

    await mongoose.connect(uri, {
        dbName: name,
        serverSelectionTimeoutMS: 15000
    });

    console.log(`[panel] ✅ MongoDB متصل (db: ${name})`);
}

// ======================================================
// 3) عميل Discord
// ======================================================

async function startClient() {
    const token = ctx.botToken();
    const client = ctx.createClient();

    client.on('error', err => console.error('[panel] discord error:', err.message));
    client.on('shardError', err => console.error('[panel] shard error:', err?.message));

    try {
        await client.login(token);
        return client;
    } catch (err) {
        console.error('\n============================================');
        console.error('  ❌ فشل دخول البوت (DISCORD_TOKEN)');
        console.error('============================================');
        console.error('  ' + (err?.message || err));
        if (/token.*invalid|TokenInvalid/i.test(String(err?.message || ''))) {
            console.error('\n  غالباً التوكن غلط أو فيه مسافات/اقتباسات.');
            console.error('  جرّب: node -e "console.log(require(\'./lib/bot-context.js\').botToken().length)"');
        }
        if (/already.*(online|authenticated)|session.*duplicate/i.test(String(err?.message || ''))) {
            console.error('\n  ⚠️  هذا التوكن متصل من مكان ثاني.');
            console.error('  ديسكورد يسمح باتصال واحد لكل توكن — إما شغّل');
            console.error('  الداشبورد داخل البوت، أو أعطِ الداشبورد توكن ثاني.');
        }
        console.error('============================================\n');
        process.exit(1);
    }
}

// ======================================================
// 4) التشغيل
// ======================================================

async function main() {
    await connectDb();

    const client = await startClient();
    console.log(`[panel] ✅ مسجّل دخول كـ ${client.user.tag} (${client.user.id})`);

    const app = express();
    app.disable('x-powered-by');

    // server.js يبني الناقص من lib/bot-context تلقائياً؛ نمرّر الـ client بس
    setupDashboard(app, { client });

    // تشغيل السيرفر
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log('');
        console.log('  ╔══════════════════════════════════════╗');
        console.log('  ║   ✅ الداشبورد شغّال (Standalone)     ║');
        console.log('  ╚══════════════════════════════════════╝');
        console.log(`     المنفذ   : ${PORT}`);
        console.log(`     التوكن   : ${client.user.tag}`);
        console.log(`     المالك   : ${process.env.OWNER_IDS}`);
        console.log(`     رابط OAuth: ${process.env.DASHBOARD_REDIRECT_URI || '(غير محدد)'}`);
        console.log('');
    });

    server.on('error', err => {
        if (err.code === 'EADDRINUSE') {
            console.error(`[panel] ❌ المنفذ ${PORT} مشغول. غيّر PORT في .env`);
        } else {
            console.error('[panel] ❌ خطأ بالسيرفر:', err.message);
        }
        process.exit(1);
    });

    // إغلاق مرتب
    const shutdown = async signal => {
        console.log(`\n[panel] ${signal} — إيقاف...`);
        server.close();
        try { await client.destroy(); } catch {}
        try { await mongoose.disconnect(); } catch {}
        process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('unhandledRejection', err => {
        console.error('[panel] unhandledRejection:', err?.message || err);
    });
}

main().catch(err => {
    console.error('[panel] ❌ فشل الإقلاع:', err);
    process.exit(1);
});
