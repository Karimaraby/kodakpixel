// سيرفر كوداك بيكسل - نظام الكاشير
// المسؤول عن: تخزين البيانات المركزية + استقبال المزامنة من كل الفروع
//
// ملحوظة مهمة عن قاعدة البيانات: النسخة دي بتستخدم Postgres (زي اللي بتوفره
// خدمة Supabase مجاناً وبشكل دائم) بدل ملف SQLite محلي. السبب: الاستضافات
// المجانية (زي Render Free) بتمسح أي ملفات محفوظة على السيرفر نفسه كل ما
// السيرفر يعيد تشغيل نفسه، فلو استخدمنا ملف SQLite هناك، بياناتك (الفواتير
// والعملاء) كانت هتتمسح بشكل دوري. بربط السيرفر بقاعدة بيانات خارجية دائمة
// (Supabase) بدل ملف محلي، البيانات بتفضل محفوظة حتى لو Render نفسه اتقفل
// وفتح تاني أو عمل إعادة تشغيل.

const express = require('express');
const cors = require('cors');
const { Pool, types } = require('pg');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

// بشكل افتراضي، مكتبة pg بترجع أعمدة BIGINT (زي أعمدة التاريخ/الوقت عندنا،
// اللي مخزّنة كميلي ثانية) كـ"نص" مش رقم، عشان أرقام BIGINT ممكن تكون أكبر
// من أكبر رقم JavaScript يقدر يمثله بدقة. بس التواريخ عندنا (ميلي ثانية منذ
// 1970) بعيدة جداً عن الحد ده، فمأمون نخليها ترجع كأرقام عادية. من غير التعديل
// ده، أي كود في الواجهة بيستخدم new Date(inv.created_at) كان هيطلع "Invalid
// Date" لإن الفرونت إند بيتوقع رقم مش نص.
types.setTypeParser(20, (val) => parseInt(val, 10)); // 20 = OID بتاع BIGINT

const app = express();
// السيرفر بيشتغل ورا بروكسي الاستضافة (زي Render)، فبنثق في هيدر X-Forwarded-For
// عشان req.ip يبقى فعلاً IP بتاع الجهاز اللي بعت الطلب، مش IP البروكسي نفسه -
// ده مهم عشان حماية محاولات تسجيل الدخول المتكررة (تحت) تشتغل صح.
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// السيرفر ده بيقدّم واجهة الكاشير (الفرونت إند) هو نفسه، عشان الموقع كله يبقى
// "حاجة واحدة" على رابط واحد: تكتب عنوان السيرفر في المتصفح، وتلاقي الكاشير
// شغال على طول، من غير ما تحتاج تفتح ملف الواجهة منفصل. لو عايز تحط الفرونت
// إند مكان تاني، غيّر المسار ده بس.
const FRONTEND_DIR = process.env.KODAK_FRONTEND_DIR || path.join(__dirname, '..', 'frontend');
app.use(express.static(FRONTEND_DIR));

// رابط الاتصال بقاعدة البيانات (Postgres) - لازم يتحدد من متغير بيئة
// DATABASE_URL (بتجيبه من صفحة الإعدادات في Supabase، اسمه "Connection string").
// لو مش موجود، السيرفر مش هيشتغل خالص ويوقف بتحذير واضح، أحسن من ما يشتغل
// ويحاول يتصل بحاجة مش موجودة.
if (!process.env.DATABASE_URL) {
  console.error('❌ خطأ: متغير البيئة DATABASE_URL مش متحدد. اتأكد إنك حاطط رابط');
  console.error('   الاتصال بقاعدة بيانات Supabase في إعدادات البيئة (Environment');
  console.error('   Variables) في Render قبل ما تشغّل السيرفر.');
  process.exit(1);
}

// Supabase بيتطلب اتصال مشفّر (SSL). rejectUnauthorized:false هنا معناها بنقبل
// شهادة Supabase من غير ما نحتاج نضيف شهادات إضافية يدوياً - ده الإعداد
// القياسي المتبع مع خدمات الاستضافة المُدارة زي Supabase وRender وHeroku.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === 'false' ? false : { rejectUnauthorized: false },
});

// السر المستخدم لتوقيع توكنات الدخول (JWT). في بيئة الإنتاج الحقيقية لازم يتحدد
// من متغير بيئة JWT_SECRET بقيمة عشوائية طويلة، مش القيمة الافتراضية دي.
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_production_kodak_pixel';
if (!process.env.JWT_SECRET) {
  console.warn('==============================================================');
  console.warn('⚠️  تحذير مهم: JWT_SECRET مش متحدد من متغيرات البيئة!');
  console.warn('⚠️  السيرفر شغال حالياً بمفتاح افتراضي معروف للعامة (موجود في الكود).');
  console.warn('⚠️  لو السيرفر ده متاح على الإنترنت، أي حد يعرف الكود يقدر يزوّر');
  console.warn('⚠️  توكن دخول مدير كامل الصلاحيات. لازم تحدد JWT_SECRET في إعدادات');
  console.warn('⚠️  البيئة (Environment Variables) بقيمة عشوائية طويلة قبل النشر الفعلي.');
  console.warn('==============================================================');
}

// نفس دالة تشفير كلمة المرور المستخدمة في الفرونت إند بالظبط (SHA-256 عادي،
// من غير bcrypt)، عشان الهاش اللي بيتولد هنا وقت تسجيل الدخول أونلاين يطابق
// تمام الهاش المخزّن أصلاً في قاعدة البيانات من نظام تسجيل الدخول الأوفلاين
// الحالي. لو غيّرنا لـ bcrypt هنا كان هيبوّظ كل الباسوردات المحفوظة قبل كده.
function sha256Hex(str) {
  return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
}

// كود استرجاع خاص بإعادة تعيين باسورد المدير لو نسيها (خاصية "نسيت كلمة
// المرور" في شاشة الدخول - للمدير بس). ده مختلف تماماً عن JWT_SECRET، وده
// مقصود: صاحب المشروع بس اللي يعرف القيمة دي (بيحطها في متغيرات البيئة على
// Render، ومش موجودة في الكود خالص)، وميديهاش لأي كاشير. لو المتغير ده مش
// متحدد، الخاصية دي بتتقفل تلقائياً (بترجع خطأ واضح) بدل ما تشتغل بقيمة
// افتراضية معروفة تبقى ثغرة أمنية.
const ADMIN_RECOVERY_CODE = process.env.ADMIN_RECOVERY_CODE || '';
if (!ADMIN_RECOVERY_CODE) {
  console.warn('⚠️  ADMIN_RECOVERY_CODE مش متحدد - خاصية "نسيت كلمة المرور" هتكون مقفولة لحد ما تحددها.');
}

// ============ إنشاء الجداول (لو مش موجودة بالفعل) ============
const SETUP_SQL = `
CREATE TABLE IF NOT EXISTS branches (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT,
  price DOUBLE PRECISION NOT NULL,
  branch_id TEXT,
  stock_qty DOUBLE PRECISION DEFAULT 0,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  invoice_number INTEGER,
  branch_id TEXT,
  customer_name TEXT,
  customer_phone TEXT,
  items_json TEXT NOT NULL,
  discount_percent DOUBLE PRECISION DEFAULT 0,
  vat_percent DOUBLE PRECISION DEFAULT 0,
  vat_amount DOUBLE PRECISION DEFAULT 0,
  total_cost DOUBLE PRECISION NOT NULL,
  paid DOUBLE PRECISION DEFAULT 0,
  remaining DOUBLE PRECISION DEFAULT 0,
  pay_method TEXT,
  status TEXT DEFAULT 'not Delivered',
  created_by TEXT,
  shift_id TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS employees_attendance (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  employee_name TEXT,
  check_in BIGINT,
  check_out BIGINT,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS investments (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  investor_name TEXT,
  amount DOUBLE PRECISION NOT NULL,
  note TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'cashier',
  branch_id TEXT,
  monthly_salary DOUBLE PRECISION DEFAULT 0,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS shifts (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  user_id TEXT,
  user_name TEXT,
  opened_at BIGINT NOT NULL,
  closed_at BIGINT,
  status TEXT DEFAULT 'open',
  summary_json TEXT,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  shift_id TEXT,
  description TEXT,
  amount DOUBLE PRECISION NOT NULL,
  category TEXT,
  created_by TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS advances (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  shift_id TEXT,
  employee_id TEXT,
  employee_name TEXT,
  amount DOUBLE PRECISION NOT NULL,
  note TEXT,
  created_by TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  settled INTEGER DEFAULT 0,
  settled_at BIGINT,
  deleted INTEGER DEFAULT 0
);

-- سجل كل عمليات تحصيل الفلوس الفعلية (وقت إنشاء الفاتورة، أو تحصيل متبقي بعدين،
-- أو تعديل يدوي من المدير). كل صف هنا مربوط بالشفت اللي اتحصّل فيه فعلياً، وده
-- اللي بيخلي حساب الكاش وقت قفل الشفت والتقارير مطابق للواقع حتى لو الفاتورة
-- نفسها اتعملت في شفت أو يوم تاني.
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY,
  invoice_id TEXT,
  branch_id TEXT,
  shift_id TEXT,
  amount DOUBLE PRECISION NOT NULL,
  method TEXT,
  note TEXT,
  created_by TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

-- الشركاء: كل شريك مرتبط بفرع معيّن، وله نسبة ثابتة من صافي ربح الفرع ده
-- (النسبة دي بتتحدد يدويًا باتفاق الشركاء، مش بتتحسب تلقائي من رأس المال).
CREATE TABLE IF NOT EXISTS partners (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  name TEXT NOT NULL,
  share_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

-- سجل توثيقي (مش حسابي) لكل مبلغ حطّه أي شريك في أي فرع، عشان يبقى معروف
-- ومحفوظ بالتاريخ قد إيه كل واحد حط فعليًا. ده منفصل تمامًا عن نسبة الربح
-- (share_percent فوق)، ومبيغيّرهاش تلقائي.
CREATE TABLE IF NOT EXISTS partner_capital (
  id TEXT PRIMARY KEY,
  partner_id TEXT,
  branch_id TEXT,
  amount DOUBLE PRECISION NOT NULL,
  note TEXT,
  created_by TEXT,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  deleted INTEGER DEFAULT 0
);

-- فرض تفرّد اسم الدخول عبر كل الفروع
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
`;

// ترقية قواعد بيانات قديمة اتعملت قبل إضافة الأعمدة دي. IF NOT EXISTS هنا
// معناها الأمر بيتنفذ بأمان حتى لو العمود موجود بالفعل، من غير أي خطأ.
const MIGRATIONS = `
ALTER TABLE users ADD COLUMN IF NOT EXISTS monthly_salary DOUBLE PRECISION DEFAULT 0;
ALTER TABLE advances ADD COLUMN IF NOT EXISTS employee_id TEXT;
ALTER TABLE advances ADD COLUMN IF NOT EXISTS settled INTEGER DEFAULT 0;
ALTER TABLE advances ADD COLUMN IF NOT EXISTS settled_at BIGINT;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS vat_percent DOUBLE PRECISION DEFAULT 0;
ALTER TABLE invoices ADD COLUMN IF NOT EXISTS vat_amount DOUBLE PRECISION DEFAULT 0;
`;

async function setupDatabase() {
  await pool.query(SETUP_SQL);
  await pool.query(MIGRATIONS);
  console.log('✅ قاعدة البيانات جاهزة (الجداول اتعملت أو موجودة بالفعل).');
}

// ============ منطق المزامنة (Sync Engine) ============
// المبدأ: كل صف عنده updated_at (وقت التعديل بالميلي ثانية).
// لما تيجي نسخة من العميل، لو وقتها أحدث من اللي في السيرفر (أو مش موجودة أصلاً) بنحدّثها.
// ده بيحل تعارض التعديلات لو حصل تعديل من فرعين في نفس الوقت (آخر تعديل بيكسب).

// بيضمن إن كل الأعمدة المطلوبة موجودة في الصف قبل ما نحاول نحفظه، حتى لو
// الصف جاي من نسخة قديمة من الواجهة وبالتالي خاصية معينة مش موجودة في
// الأوبجكت خالص - بنحطها null بدل ما نخلي الاستعلام يفشل.
function normalizeRow(row, columns) {
  return columns.map(c => (row[c] === undefined ? null : row[c]));
}

// ملحوظة مهمة (إصلاح باج): أي INSERT بيفشل جوه معاملة (Transaction) في Postgres
// بيخلي المعاملة كلها تدخل في حالة "aborted" - أي أمر تاني بعده (حتى لو سليم
// 100%) بيترفض برسالة "current transaction is aborted...". يعني لو حصل خطأ في
// صف واحد بس وسيبناه يمر من غير SAVEPOINT، كل باقي المزامنة (كل الجداول
// التانية كمان) بتفشل وتترجع بالكامل. عشان كده كل صف بيتحفظ جوه SAVEPOINT
// خاص بيه: لو الصف فشل، بنرجع (ROLLBACK) للنقطة دي بس، وباقي الصفوف والجداول
// بيكملوا عادي وكأن حاجة ماحصلتش.
async function upsertRows(client, table, rows, columns) {
  if (!rows || rows.length === 0) return { skipped: [] };
  const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
  const updateSet = columns.filter(c => c !== 'id').map(c => `${c}=excluded.${c}`).join(', ');
  const sql = `
    INSERT INTO ${table} (${columns.join(', ')})
    VALUES (${placeholders})
    ON CONFLICT (id) DO UPDATE SET ${updateSet}
    WHERE excluded.updated_at > ${table}.updated_at
  `;
  const skipped = [];
  for (const item of rows) {
    await client.query('SAVEPOINT sp_row_upsert');
    try {
      await client.query(sql, normalizeRow(item, columns));
      await client.query('RELEASE SAVEPOINT sp_row_upsert');
    } catch (err) {
      await client.query('ROLLBACK TO SAVEPOINT sp_row_upsert');
      console.warn(`⚠️  تم تجاهل صف فشل حفظه أثناء المزامنة في جدول ${table}: id=${item.id} (${err.message})`);
      skipped.push({ id: item.id, table, message: err.message });
    }
  }
  return { skipped };
}

// معالجة خاصة لجدول المستخدمين: لو حصل تعارض في اسم الدخول (مثلاً فرعين
// أنشأوا يوزر بنفس الاسم أوفلاين)، بنتجاهل السطر ده بس من غير ما نوقف باقي المزامنة.
// (نفس مبدأ SAVEPOINT فوق، عشان تعارض اسم الدخول مايبوظش باقي المزامنة).
async function upsertUsers(client, rows) {
  if (!rows || rows.length === 0) return { skipped: [] };
  const columns = TABLE_SCHEMAS.users;
  const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
  const updateSet = columns.filter(c => c !== 'id').map(c => `${c}=excluded.${c}`).join(', ');
  const sql = `
    INSERT INTO users (${columns.join(', ')})
    VALUES (${placeholders})
    ON CONFLICT (id) DO UPDATE SET ${updateSet}
    WHERE excluded.updated_at > users.updated_at
  `;
  const skipped = [];
  for (const item of rows) {
    await client.query('SAVEPOINT sp_user_upsert');
    try {
      await client.query(sql, normalizeRow(item, columns));
      await client.query('RELEASE SAVEPOINT sp_user_upsert');
    } catch (err) {
      await client.query('ROLLBACK TO SAVEPOINT sp_user_upsert');
      if (err.message && err.message.includes('duplicate key value violates unique constraint') && err.message.includes('username')) {
        console.warn(`⚠️  تم تجاهل تعارض اسم الدخول أثناء المزامنة: user ${item.id} (${item.username})`);
        skipped.push({ id: item.id, username: item.username });
        continue; // نكمل باقي السطور بدل ما نفشل المزامنة كلها
      }
      // أي خطأ تاني (مش تعارض اسم الدخول): سجّليه وكملي باقي الصفوف بدل ما
      // نوقف المزامنة كلها لأجل يوزر واحد بس فيه مشكلة غير متوقعة.
      console.warn(`⚠️  تم تجاهل صف يوزر فشل حفظه أثناء المزامنة: id=${item.id} (${err.message})`);
      skipped.push({ id: item.id, username: item.username, message: err.message });
    }
  }
  return { skipped };
}

// جلب أي صفوف اتحدثت بعد وقت معين (عشان نبعتها للعميل)
async function getUpdatedSince(table, since) {
  const { rows } = await pool.query(`SELECT * FROM ${table} WHERE updated_at > $1`, [since || 0]);
  return rows;
}

const TABLE_SCHEMAS = {
  branches: ['id', 'name', 'address', 'updated_at', 'deleted'],
  products: ['id', 'name', 'code', 'price', 'branch_id', 'stock_qty', 'updated_at', 'deleted'],
  invoices: ['id', 'invoice_number', 'branch_id', 'customer_name', 'customer_phone', 'items_json', 'discount_percent', 'vat_percent', 'vat_amount', 'total_cost', 'paid', 'remaining', 'pay_method', 'status', 'created_by', 'shift_id', 'created_at', 'updated_at', 'deleted'],
  employees_attendance: ['id', 'branch_id', 'employee_name', 'check_in', 'check_out', 'updated_at', 'deleted'],
  investments: ['id', 'branch_id', 'investor_name', 'amount', 'note', 'created_at', 'updated_at', 'deleted'],
  users: ['id', 'name', 'username', 'password_hash', 'role', 'branch_id', 'monthly_salary', 'updated_at', 'deleted'],
  shifts: ['id', 'branch_id', 'user_id', 'user_name', 'opened_at', 'closed_at', 'status', 'summary_json', 'updated_at', 'deleted'],
  expenses: ['id', 'branch_id', 'shift_id', 'description', 'amount', 'category', 'created_by', 'created_at', 'updated_at', 'deleted'],
  advances: ['id', 'branch_id', 'shift_id', 'employee_id', 'employee_name', 'amount', 'note', 'created_by', 'created_at', 'updated_at', 'settled', 'settled_at', 'deleted'],
  payments: ['id', 'invoice_id', 'branch_id', 'shift_id', 'amount', 'method', 'note', 'created_by', 'created_at', 'updated_at', 'deleted'],
  partners: ['id', 'branch_id', 'name', 'share_percent', 'updated_at', 'deleted'],
  partner_capital: ['id', 'partner_id', 'branch_id', 'amount', 'note', 'created_by', 'created_at', 'updated_at', 'deleted'],
};

// ============ المصادقة (تسجيل الدخول أونلاين + JWT) ============
// ملحوظة مهمة: النظام الأساسي بيشتغل أوفلاين-فيرست، وتسجيل الدخول العادي بيتم
// محلياً في الفرونت إند من غير ما يحتاج نت. الـ endpoint ده إضافي: لو الجهاز
// أونلاين وقت تسجيل الدخول، بيجيب توكن من السيرفر ويستخدمه بعد كده في المزامنة
// عشان يثبت هويته وصلاحيته للسيرفر (مش بس يعتمد على كلام الجهاز نفسه).

// حماية بسيطة ضد محاولات تخمين كلمة المرور بالتكرار (Brute-force)، مهمة جداً
// دلوقتي إن السيرفر بقى متاح على الإنترنت لأي حد. بنعدّ المحاولات الفاشلة لكل
// (IP + اسم مستخدم) خلال آخر 10 دقايق؛ لو عدّت 8 محاولات فاشلة، بنرفض أي
// محاولة تانية لمدة 10 دقايق كمان. الذاكرة دي بترجع فاضية لو السيرفر اتعمله
// إعادة تشغيل، وده مقبول (مش الهدف حماية دائمة، الهدف بس إبطاء أي هجوم آلي).
const loginAttempts = new Map(); // key -> { count, firstAttemptAt }
const LOGIN_WINDOW_MS = 10 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 8;

function loginRateLimitKey(req, username) {
  return `${req.ip}::${(username || '').toLowerCase()}`;
}
function isRateLimited(key) {
  const entry = loginAttempts.get(key);
  if (!entry) return false;
  if (Date.now() - entry.firstAttemptAt > LOGIN_WINDOW_MS) {
    loginAttempts.delete(key);
    return false;
  }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}
function recordFailedLogin(key) {
  const entry = loginAttempts.get(key);
  if (!entry || Date.now() - entry.firstAttemptAt > LOGIN_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, firstAttemptAt: Date.now() });
  } else {
    entry.count++;
  }
}
function clearFailedLogins(key) {
  loginAttempts.delete(key);
}

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'اكتب اسم الدخول وكلمة المرور' });
    }
    const rlKey = loginRateLimitKey(req, username);
    if (isRateLimited(rlKey)) {
      return res.status(429).json({ error: 'محاولات كتير غلط، حاول تاني بعد شوية' });
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1 AND deleted = 0', [username]);
    const user = rows[0];
    if (!user) {
      recordFailedLogin(rlKey);
      return res.status(400).json({ error: 'المستخدم غير موجود' });
    }
    if (sha256Hex(password) !== user.password_hash) {
      recordFailedLogin(rlKey);
      return res.status(400).json({ error: 'كلمة المرور غير صحيحة' });
    }
    clearFailedLogins(rlKey);
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, branch_id: user.branch_id },
      JWT_SECRET,
      { expiresIn: '30d' } // مدة طويلة عشان تناسب شغل الكاشير أوفلاين لفترات طويلة بين تسجيل الدخول والتاني
    );
    res.json({
      token,
      user: { id: user.id, name: user.name, username: user.username, role: user.role, branch_id: user.branch_id }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'login_failed', message: err.message });
  }
});

// ============ إعادة تعيين باسورد المدير (نسيت كلمة المرور) ============
// بيشتغل بس لحساب لـه role = 'admin'، وبيحتاج "كود الاسترجاع" اللي محدد في
// متغيرات البيئة (ADMIN_RECOVERY_CODE) - مش أي حد يعرفه، بس صاحب المشروع.
// بعد النجاح، بيرجع صف اليوزر المحدّث كامل عشان الفرونت إند يحفظه محلياً على
// طول (idbPut) - وده اللي بيخلي الجهاز ده يقدر يدخل بالباسورد الجديدة فوراً
// حتى لو مالوش توكن مزامنة صالح أصلاً (وده بالظبط سبب المشكلة اللي بيحلها).
const resetAttempts = new Map(); // نفس فكرة حماية تسجيل الدخول، مستقلة عنها
function resetRateLimitKey(req) { return `reset::${req.ip}`; }
function isResetRateLimited(key) {
  const entry = resetAttempts.get(key);
  if (!entry) return false;
  if (Date.now() - entry.firstAttemptAt > LOGIN_WINDOW_MS) { resetAttempts.delete(key); return false; }
  return entry.count >= LOGIN_MAX_ATTEMPTS;
}
function recordFailedReset(key) {
  const entry = resetAttempts.get(key);
  if (!entry || Date.now() - entry.firstAttemptAt > LOGIN_WINDOW_MS) {
    resetAttempts.set(key, { count: 1, firstAttemptAt: Date.now() });
  } else {
    entry.count++;
  }
}

app.post('/api/auth/admin-reset-password', async (req, res) => {
  try {
    if (!ADMIN_RECOVERY_CODE) {
      return res.status(503).json({ error: 'feature_disabled', message: 'خاصية استرجاع الباسورد مش مفعّلة على السيرفر ده. لازم تحدد ADMIN_RECOVERY_CODE في إعدادات البيئة على Render الأول.' });
    }
    const { username, recoveryCode, newPassword } = req.body || {};
    if (!username || !recoveryCode || !newPassword) {
      return res.status(400).json({ error: 'اكتب اسم الدخول وكود الاسترجاع وكلمة المرور الجديدة' });
    }
    if (newPassword.length < 4) {
      return res.status(400).json({ error: 'كلمة المرور الجديدة قصيرة جداً' });
    }
    const rlKey = resetRateLimitKey(req);
    if (isResetRateLimited(rlKey)) {
      return res.status(429).json({ error: 'محاولات كتير غلط، حاول تاني بعد شوية' });
    }
    if (recoveryCode !== ADMIN_RECOVERY_CODE) {
      recordFailedReset(rlKey);
      return res.status(401).json({ error: 'كود الاسترجاع غير صحيح' });
    }
    const { rows } = await pool.query('SELECT * FROM users WHERE username = $1 AND deleted = 0', [username]);
    const user = rows[0];
    const newHash = sha256Hex(newPassword);
    const updatedAt = Date.now();

    if (!user) {
      // الحساب مش موجود على السيرفر خالص (مثلاً اتمسح بالغلط من Supabase، أو
      // فقد أثناء مشاكل مزامنة قديمة). بما إن كود الاسترجاع صح، بننشئه من جديد
      // كمدير - ده بيحل نفس مشكلة "نسيت الباسورد" في الحالة دي كمان.
      const newId = 'id_' + Date.now().toString(36) + '_' + crypto.randomBytes(4).toString('hex');
      const newUser = { id: newId, name: username, username, password_hash: newHash, role: 'admin', branch_id: null, monthly_salary: 0, updated_at: updatedAt, deleted: 0 };
      try {
        await pool.query(
          'INSERT INTO users (id, name, username, password_hash, role, branch_id, monthly_salary, updated_at, deleted) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
          [newUser.id, newUser.name, newUser.username, newUser.password_hash, newUser.role, newUser.branch_id, newUser.monthly_salary, newUser.updated_at, newUser.deleted]
        );
      } catch (insertErr) {
        console.error(insertErr);
        return res.status(500).json({ error: 'reset_failed', message: insertErr.message });
      }
      return res.json({ ok: true, recreated: true, user: newUser });
    }
    if (user.role !== 'admin') {
      // الخاصية دي مقصورة على حسابات المدير بس، زي ما طُلب.
      return res.status(403).json({ error: 'الخاصية دي متاحة لحسابات المدير بس' });
    }
    await pool.query('UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3', [newHash, updatedAt, user.id]);
    res.json({
      ok: true,
      user: { id: user.id, name: user.name, username: user.username, password_hash: newHash, role: user.role, branch_id: user.branch_id, monthly_salary: user.monthly_salary, updated_at: updatedAt, deleted: 0 }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'reset_failed', message: err.message });
  }
});

// بيتحقق من التوكن لو موجود، لكن من غير ما يرفض الطلب لو مش موجود (اختياري).
// السبب: أجهزة أوفلاين ممكن تعمل مزامنة قبل أول تسجيل دخول أونلاين للموظف
// اللي عليها، أو أجهزة قديمة لسه ما حدّثتش. بنفضّل نكمل مزامنة البيانات
// العادية في الحالة دي، وبس نطبّق تحقق الصلاحيات الإضافي (تحت) لو فيه توكن.
function optionalAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) { req.user = null; return next(); }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    req.user = err ? null : decoded;
    next();
  });
}

// العميل بيبعت: { since: 123456, branches: [...], products: [...], invoices: [...] }
// السيرفر بيرد: { serverTime: now, branches: [...تحديثات...], products: [...], invoices: [...] }
//
// تحقق صلاحيات إضافي على مستوى السيرفر (طبقة حماية ثانية فوق حماية الفرونت
// إند، مش بديل عنها): لو الطلب جاي بتوكن صالح ومعروف إن صاحبه كاشير عادي (مش
// admin)، بنمنعه من: (أ) إضافة/تعديل مستخدمين أو فروع أو منتجات، (ب) إرسال أي
// صف عليه "deleted=1" (يعني عملية حذف) في أي جدول. الصفوف دي بس بتتجاهل
// (skip) من غير ما توقف باقي المزامنة، بالظبط زي التعامل مع تعارض اسم الدخول.
const ADMIN_ONLY_TABLES = new Set(['users', 'branches', 'products', 'partners', 'partner_capital']);

function filterRowsForRole(table, rows, user) {
  if (!user || user.role === 'admin') return rows; // مفيش توكن، أو المستخدم مدير أصلاً
  return rows.filter(row => {
    if (ADMIN_ONLY_TABLES.has(table)) return false; // كاشير عادي مايضيفش/يعدّلش يوزرز/فروع/منتجات
    if (row && row.deleted === 1) return false;     // كاشير عادي مايبعتش عمليات حذف
    return true;
  });
}

// حماية أساسية قبل ما السيرفر يبقى متاح على الإنترنت لأي حد: لازم توكن دخول
// صالح عشان تقرأ أو تزامن البيانات، وإلا أي حد عنده رابط السيرفر (حتى من غير
// اسم مستخدم أو كلمة سر) كان يقدر يسحب قاعدة البيانات كاملة (فواتير، أرقام
// هواتف عملاء، هاشات كلمات مرور... إلخ) عن طريق POST /api/sync بس.
// الاستثناء الوحيد: أول تشغيل للسيرفر خالص (قاعدة البيانات فاضية تماماً من
// المستخدمين، يعني لسه محدش سجّل حتى) - في الحالة دي بس بنسمح بمزامنة من غير
// توكن، عشان أول جهاز يشتغل عليه Karim يقدر "يزرع" الحساب الأول بتاعه على
// السيرفر أصلاً (وإلا هيبقى مستحيل يجيب توكن من الأول). بمجرد ما أول مستخدم
// يتسجل على السيرفر، الاستثناء ده بيتقفل تلقائياً للأبد.
async function serverHasAnyUser() {
  const { rows } = await pool.query('SELECT COUNT(*) as c FROM users WHERE deleted = 0');
  return parseInt(rows[0].c, 10) > 0;
}

async function requireAuthUnlessBootstrapping(req, res, next) {
  if (req.user) return next(); // توكن صالح، اتفضل
  try {
    if (!(await serverHasAnyUser())) return next(); // قاعدة بيانات فاضية تماماً - أول تشغيل، مسموح
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'server_error', message: err.message });
  }
  return res.status(401).json({ error: 'unauthorized', message: 'لازم تسجّل الدخول الأول عشان تقدر تزامن البيانات' });
}

app.post('/api/sync', optionalAuth, requireAuthUnlessBootstrapping, async (req, res) => {
  const client = await pool.connect();
  try {
    const body = req.body || {};
    const since = body.since || 0;
    let skippedUsers = [];

    await client.query('BEGIN');
    for (const table of Object.keys(TABLE_SCHEMAS)) {
      if (!Array.isArray(body[table])) continue;
      const allowedRows = filterRowsForRole(table, body[table], req.user);
      if (table === 'users') {
        const result = await upsertUsers(client, allowedRows);
        skippedUsers = result.skipped;
      } else {
        await upsertRows(client, table, allowedRows, TABLE_SCHEMAS[table]);
      }
    }
    await client.query('COMMIT');

    const response = { serverTime: Date.now() };
    if (skippedUsers.length) response.skippedUsers = skippedUsers;
    for (const table of Object.keys(TABLE_SCHEMAS)) {
      response[table] = await getUpdatedSince(table, since);
    }

    res.json(response);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'sync_failed', message: err.message });
  } finally {
    client.release();
  }
});

// نقطة لتحميل كل البيانات من الصفر (أول مرة يفتح فيها فرع جديد)
app.get('/api/full-state', optionalAuth, requireAuthUnlessBootstrapping, async (req, res) => {
  try {
    const response = { serverTime: Date.now() };
    for (const table of Object.keys(TABLE_SCHEMAS)) {
      const { rows } = await pool.query(`SELECT * FROM ${table} WHERE deleted = 0`);
      response[table] = rows;
    }
    res.json(response);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'full_state_failed', message: err.message });
  }
});

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, time: Date.now(), db: 'connected' });
  } catch (err) {
    res.status(500).json({ ok: false, time: Date.now(), db: 'disconnected', message: err.message });
  }
});

const PORT = process.env.PORT || 4000;
setupDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`✅ سيرفر كوداك بيكسل شغال على المنفذ ${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ فشل الاتصال بقاعدة البيانات أو إعدادها عند بدء التشغيل:', err);
    process.exit(1);
  });
