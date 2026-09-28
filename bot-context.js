'use strict';
// ======================================================
// سياق البوت — يربط الداشبورد بعميل Discord وقاعدة البيانات
// ======================================================
// وضعان:
//   1) mounted  : الداشبورد داخل عملية البوت (index.js يمرّر deps جاهزة)
//   2) standalone: الداشبورد على استضافة ثانية → يبني كل شي لحاله من .env
//      (توكن + OWNER_IDS + MONGO_URI + إعدادات OAuth)
//
// الفكرة: كل نفس `deps` اللي index.js كان يمرّره، نقدر نبنيه هنا بنفس
// التواقيع — فـ server.js ما يفرق بين الوضعين.

const {
    Client,
    GatewayIntentBits,
    Partials,
    EmbedBuilder,
    ChannelType,
    PermissionsBitField
} = require('discord.js');

const { GuildSettings, JailData, DashboardUser, DashboardLog } = require('./db.js');
const { DEFAULT_PROTECTIONS, ensureMetricMaps } = require('./protections.js');

// ======================================================
// ENV
// ======================================================

// ينظّف التوكن من BOM/اقتباسات/مسافات (نفس منطق البوت — لو الاستضافة
// لصقت "DISCORD_TOKEN=" جوّه القيمة)
function cleanTokenValue(value) {
    let s = String(value == null ? '' : value);
    s = s.replace(/^\uFEFF/, '');
    s = s.replace(/^['"]|['"]$/g, '');
    s = s.replace(/^DISCORD_TOKEN\s*=\s*/i, '');
    s = s.replace(/^TOKEN\s*=\s*/i, '');
    s = s.replace(/\s+/g, '');
    return s.trim();
}

function botToken() {
    return cleanTokenValue(process.env.DISCORD_TOKEN || process.env.TOKEN);
}

function ownerIds() {
    return String(process.env.OWNER_IDS || process.env.OWNER_ID || '')
        .split(',')
        .map(v => cleanTokenValue(v))
        .filter(v => /^\d{15,21}$/.test(v));
}

function staffRoleName() {
    return process.env.STAFF_ROLE_NAME || 'ستريتر';
}

// ======================================================
// عميل Discord (للوضع المستقل فقط)
// ======================================================

function createClient() {
    return new Client({
        intents: [
            GatewayIntentBits.Guilds,
            GatewayIntentBits.GuildMembers,
            GatewayIntentBits.GuildMessages,
            GatewayIntentBits.GuildModeration,
            GatewayIntentBits.MessageContent,
            GatewayIntentBits.GuildVoiceStates
        ],
        partials: [Partials.Channel, Partials.Message],
        // نسمح eloquent بإعادة الاتصال لو الشبكة طارت
        rest: { timeout: 30000, retries: 5 }
    });
}

// ======================================================
// الصلاحيات (نسخة نظيفة — بدون كاش، كل نداء يسأل ديسكورد)
// ======================================================

function getStaffRole(guild) {
    return guild?.roles?.cache?.find(
        role => role.name === staffRoleName()
    ) || null;
}

// مالك السيرفر / Administrator / رتبته فوق رتبة البوت
function isServerAdmin(member, guild) {
    if (!member || !guild) return false;
    if (member.id === guild.ownerId) return true;
    if (member.permissions?.has(PermissionsBitField.Flags.Administrator)) return true;

    const botHighest = guild?.members?.me?.roles?.highest;
    if (botHighest && member.roles?.highest?.position > botHighest.position) return true;

    return false;
}

function memberHasStaffRole(member, guild) {
    if (!member || !guild) return false;
    const staffRole = getStaffRole(guild);
    if (!staffRole) return false;
    return member.roles.cache.has(staffRole.id);
}

function hasStaffAccess(member, guild) {
    return memberHasStaffRole(member, guild) || isServerAdmin(member, guild);
}

async function getMember(guild, userId) {
    return guild.members.fetch(userId).catch(() => null);
}

function normalizeText(text) {
    return String(text || '')
        .trim()
        .replace(/\s+/g, ' ')
        .toLowerCase();
}

// ======================================================
// الإعدادات
// ======================================================

function ensureProtections(settings) {
    if (!settings.protections) {
        settings.protections = JSON.parse(JSON.stringify(DEFAULT_PROTECTIONS));
        return settings.protections;
    }

    for (const key of Object.keys(DEFAULT_PROTECTIONS)) {
        if (settings.protections[key] === undefined) {
            settings.protections[key] = JSON.parse(
                JSON.stringify(DEFAULT_PROTECTIONS[key])
            );
        }
    }

    if (ensureMetricMaps(settings.protections)) {
        settings.markModified('protections');
        settings.save().catch(() => {});
    }

    return settings.protections;
}

async function getSettings(guildId) {
    let settings = await GuildSettings.findById(guildId).catch(() => null);

    if (!settings) {
        settings = new GuildSettings({ _id: guildId });
    }

    // حقول مصفوفة كانت تجي كائن من قواعد قديمة → نصلّحها
    if (!Array.isArray(settings.shortcuts)) {
        settings.shortcuts = [];
        settings.markModified('shortcuts');
    }

    if (!Array.isArray(settings.autoResponses)) {
        settings.autoResponses = [];
        settings.markModified('autoResponses');
    }

    ensureProtections(settings);

    return settings;
}

// ======================================================
// اللوق
// ======================================================

async function sendLog(guild, type, title, description, color = 0x5865F2) {
    try {
        const settings = await GuildSettings.findById(guild.id).catch(() => null);
        if (!settings) return;

        const channelId = settings.logs?.[type];
        if (!channelId) return;

        const channel = guild.channels.cache.get(channelId);
        if (!channel || !channel.isTextBased()) return;

        await channel.send({
            embeds: [
                new EmbedBuilder()
                    .setTitle(title)
                    .setDescription(description)
                    .setColor(color)
                    .setTimestamp()
            ]
        }).catch(() => {});
    } catch (err) {
        console.error('[panel] log error:', err.message);
    }
}

// ======================================================
// السفر (jail)
// ======================================================

async function applyJailRolePermissions(guild, role) {
    for (const channel of guild.channels.cache.values()) {
        if (!channel.isTextBased()) continue;
        await channel.permissionOverwrites.edit(role, {
            ViewChannel: false,
            SendMessages: false,
            AddReactions: false,
            Speak: false
        }).catch(() => {});
    }
}

async function getJailRole(guild, { create = true } = {}) {
    let role = guild.roles.cache.find(r => r.name === 'سجن');

    if (!role && create) {
        role = await guild.roles.create({
            name: 'سجن',
            color: 0x808080,
            reason: 'Cypher Security — رتبة السفر'
        }).catch(() => null);

        if (role) await applyJailRolePermissions(guild, role);
    }

    return role || null;
}

async function jailMember(member) {
    const guild = member.guild;

    const existing = await JailData.findOne({
        guildId: guild.id,
        userId: member.id
    });

    if (!existing) {
        const roles = member.roles.cache
            .filter(role => role.id !== guild.id)
            .map(role => role.id);

        await JailData.create({ guildId: guild.id, userId: member.id, roles });
    }

    const jailRole = await getJailRole(guild);
    if (!jailRole) return null;

    const removable = member.roles.cache.filter(
        role => role.id !== guild.id && role.id !== jailRole.id && role.editable
    );

    await member.roles.remove(removable, 'Jail').catch(() => {});
    await member.roles.add(jailRole, 'Jail');

    return jailRole;
}

async function unjailMember(member) {
    const guild = member.guild;

    const data = await JailData.findOne({
        guildId: guild.id,
        userId: member.id
    });

    if (!data) return false;

    const jailRole = await getJailRole(guild, { create: false });

    if (jailRole && member.roles.cache.has(jailRole.id)) {
        await member.roles.remove(jailRole, 'Unjail').catch(() => {});
    }

    const roles = data.roles
        .map(id => guild.roles.cache.get(id))
        .filter(Boolean)
        .filter(role => role.editable);

    if (roles.length) {
        await member.roles.add(roles, 'Restore roles after unjail').catch(() => {});
    }

    await JailData.deleteOne({ guildId: guild.id, userId: member.id });

    return true;
}

// ======================================================
// التصدير
// ======================================================

// يبني كائن deps بنفس تواقيع index.js
function buildDeps({ client, ticketHandler = null, setRuntimeDashboardUrl = null } = {}) {
    if (!client) throw new Error('buildDeps: لازم تمرّر client');

    const deps = {
        client,
        GuildSettings,
        DashboardUser,
        DashboardLog,
        JailData,
        getSettings,
        ensureProtections,
        sendLog,
        jailMember,
        unjailMember,
        isServerAdmin,
        memberHasStaffRole,
        hasStaffAccess,
        getMember,
        normalizeText,
        STAFF_ROLE_NAME: staffRoleName(),
        OWNER_ID: ownerIds()[0] || '',
        OWNER_IDS: ownerIds(),
        EmbedBuilder,
        ChannelType,
        PermissionsBitField,
        // اختياري: نفس دوال البوت لو موجودة
        tickets: ticketHandler,
        setRuntimeDashboardUrl: setRuntimeDashboardUrl || (() => {})
    };

    return deps;
}

module.exports = {
    // env
    cleanTokenValue,
    botToken,
    ownerIds,
    staffRoleName,
    // discord
    createClient,
    getStaffRole,
    isServerAdmin,
    memberHasStaffRole,
    hasStaffAccess,
    getMember,
    normalizeText,
    // settings
    getSettings,
    ensureProtections,
    // logs
    sendLog,
    // jail
    getJailRole,
    applyJailRolePermissions,
    jailMember,
    unjailMember,
    // models
    GuildSettings,
    JailData,
    DashboardUser,
    DashboardLog,
    // factory
    buildDeps
};
