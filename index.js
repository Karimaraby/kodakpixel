// نقطة الدخول لما السيرفر يبقى منشور على Vercel. Vercel بيحوّل أي طلب رابطه
// بيبدأ بـ /api/... للملف ده (شوف vercel.json)، وهو بس بيمرر الطلب لنفس
// تطبيق Express المعرّف في app.js (نفس الراوتس بالظبط اللي شغالة على Render).
const { app } = require('../app');

module.exports = app;
