'use strict';
// ======================================================
// قاعدة البيانات والموديلات — نسخة الداشبورد
// ======================================================
// مولّد تلقائياً من index.js (نسخة حرفية). عدّل المصدر index.js ثم:
//   node tools/sync-panel-lib.js
//
// التسجيل بـ `mongoose.models.X || mongoose.model(...)` عشان:
//   - لو البوت سجّل نفس الموديل قبل (require من index.js) نرجع لنفس
//     الـ instance بدل OverwriteModelError
//   - ما ينفصل مونجوز عن البوت: نفس الـ pool ونفس الكاش

const mongoose = require('mongoose');

const guildSchema = new mongoose.Schema({
    _id: {
        type: String,
        required: true
    },

    welcome: {
        enabled: {
            type: Boolean,
            default: false
        },

        channelId: {
            type: String,
            default: null
        },

        message: {
            type: String,
            default: 'أهلاً بك {user} في السيرفر ❤️'
        },

        cardEnabled: {
            type: Boolean,
            default: true
        },

        image: {
            type: String,
            default: null
        }
    },

    logs: {
        voice: {
            type: String,
            default: null
        },

        role: {
            type: String,
            default: null
        },

        channel: {
            type: String,
            default: null
        },

        webhook: {
            type: String,
            default: null
        },

        member: {
            type: String,
            default: null
        },

        moderation: {
            type: String,
            default: null
        },

        message: {
            type: String,
            default: null
        },

        protection: {
            type: String,
            default: null
        }
    },

    autoResponses: {
        type: [
            {
                trigger: String,
                response: String,
                staffOnly: {
                    type: Boolean,
                    default: false
                }
            }
        ],
        default: []
    },

    shortcuts: {
        type: [
            {
                name: String,
                command: String
            }
        ],
        default: []
    },

    levelSettings: {
        enabled: {
            type: Boolean,
            default: true
        },

        messagesPerLevel: {
            type: Number,
            default: 50
        },

        rewards: {
            type: Map,
            of: String,
            default: new Map()
        }
    },

    protections: {
        channels: {
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            action: { type: String, default: 'ban' },
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        },
        roles: {
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            action: { type: String, default: 'ban' },
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        },
        bans: {
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 3 },
            action: { type: String, default: 'kick' },
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        },
        bots: {
            enabled: { type: Boolean, default: false },
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        },
        spam: {
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            timeframe: { type: Number, default: 5000 },
            maxLength: { type: Number, default: 400 },
            repeatedChar: { type: Number, default: 8 },
            action: { type: String, default: 'timeout' },
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        },
        webhooks: {
            enabled: { type: Boolean, default: false },
            limit: { type: Number, default: 5 },
            action: { type: String, default: 'ban' },
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        },
        invites: {
            enabled: { type: Boolean, default: false },
            code: { type: String, default: null },
            channelId: { type: String, default: null },
            action: { type: String, default: 'ban' },
            // ⛔ مافيها تجاوز ولا حد تأخير: أول ما ينحذف الاختصار = عقوبة فورية
            // (الاستثناء الوحيد: راعي البوت)
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        },
        scams: {
            enabled: { type: Boolean, default: false },
            // الرومات المحمية — لازم واحد على الأقل للتفعيل
            channelIds: { type: [String], default: [] },
            // القاعدة لكل نوع محتوى (كل وحدة مفعّلة/معطّلة لحالها)
            onTalk: { type: Boolean, default: false },
            onImage: { type: Boolean, default: false },
            onLink: { type: Boolean, default: false },
            action: { type: String, default: 'ban' },
            metrics: { type: mongoose.Schema.Types.Mixed, default: {} },
            metricActions: { type: mongoose.Schema.Types.Mixed, default: {} }
        }
    },

    tickets: {
        enabled: { type: Boolean, default: false },
        panelChannelId: { type: String, default: null },
        categoryId: { type: String, default: null },
        supportRoleId: { type: String, default: null },
        logChannelId: { type: String, default: null },
        welcomeMessage: { type: String, default: 'أهلاً بك 👋 اشرح مشكلتك وسيقوم الفريق بمساعدتك بأقرب وقت.' },
        panelImage: { type: String, default: null },
        welcomeImage: { type: String, default: null },
        panelMessageId: { type: String, default: null },
        maxPerUser: { type: Number, default: 1 },
        options: {
            type: [
                {
                    key: { type: String, default: null },
                    label: { type: String, default: 'تكت' },
                    description: { type: String, default: '' },
                    emoji: { type: String, default: '🎫' },
                    staffOnly: { type: Boolean, default: false },
                    // ⏸️ معلق: الزر يبقى باللوحة بس معطّل — ولا يفتح تكت
                    suspended: { type: Boolean, default: false }
                }
            ],
            default: []
        }
    },

    autoRole: {
        enabled: {
            type: Boolean,
            default: false
        },
        roleId: {
            type: String,
            default: null
        }
    },

    whitelist: {
        type: [String],
        default: []
    }
});

const GuildSettings = mongoose.models.GuildSettings || mongoose.model(
    'GuildSettings',
    guildSchema
);


const jailSchema = new mongoose.Schema({
    guildId: String,
    userId: String,
    roles: [String]
});

const JailData = mongoose.models.JailData || mongoose.model(
    'JailData',
    jailSchema
);


const levelSchema = new mongoose.Schema({
    guildId: String,
    userId: String,
    messages: {
        type: Number,
        default: 0
    },
    level: {
        type: Number,
        default: 0
    }
});

const UserLevel = mongoose.models.UserLevel || mongoose.model(
    'UserLevel',
    levelSchema
);

// نسخة احتياطية كاملة للسيرفر (قنوات + رتب) للاسترجاع اليدوي بعد التهكير
const backupSchema = new mongoose.Schema({
    guildId: {
        type: String,
        required: true
    },
    capturedAt: {
        type: Date,
        default: Date.now
    },
    channels: {
        type: mongoose.Schema.Types.Mixed,
        default: []
    },
    roles: {
        type: mongoose.Schema.Types.Mixed,
        default: []
    },
    emojis: {
        type: mongoose.Schema.Types.Mixed,
        default: []
    },
    stickers: {
        type: mongoose.Schema.Types.Mixed,
        default: []
    },
    protections: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    }
});

backupSchema.index({ guildId: 1 }, { unique: true });

const GuildBackup = mongoose.models.GuildBackup || mongoose.model(
    'GuildBackup',
    backupSchema
);


// سيرفرات المستخدم المحفوظة في الداشبورد (كاش فوري عند الدخول ثانية)
const dashboardUserSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true,
        unique: true
    },
    guilds: {
        type: mongoose.Schema.Types.Mixed,
        default: []
    },
    username: String,
    authorized: {
        type: Boolean,
        default: true
    },
    authorizedAt: Date,
    authorizedGuilds: {
        type: [String],
        default: []
    },
    loginCount: {
        type: Number,
        default: 0
    },
    lastLoginAt: Date,
    lastLoginIp: String,
    lastLoginDevice: String,
    firstLoginAt: Date,
    firstLoginIp: String,
    firstLoginDevice: String,
    firstLoginNotificationSentAt: Date,
    firstLoginNotificationPending: Boolean,
    firstLoginNotificationPendingAt: Date,
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const DashboardUser = mongoose.models.DashboardUser || mongoose.model(
    'DashboardUser',
    dashboardUserSchema
);


// سجل تعديلات الداشبورد (من عدّل ماذا ومتى)
const dashboardLogSchema = new mongoose.Schema({
    guildId: {
        type: String,
        index: true
    },
    userId: String,
    username: String,
    action: String,
    details: String,
    createdAt: {
        type: Date,
        default: Date.now
    }
});

dashboardLogSchema.index({ guildId: 1, createdAt: -1 });

const DashboardLog = mongoose.models.DashboardLog || mongoose.model(
    'DashboardLog',
    dashboardLogSchema
);
module.exports = {
    GuildSettings,
    JailData,
    UserLevel,
    GuildBackup,
    DashboardUser,
    DashboardLog
};
