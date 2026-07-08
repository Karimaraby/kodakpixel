// سيرفر كوداك بيكسل - نظام الكاشير
// المسؤول عن: تخزين البيانات المركزية + استقبال المزامنة من كل الفروع

const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
// السيرفر بيشتغل ورا بروكسي الاستضافة (زي Render)، فبنثق في هيدر X-Forwarded-For
// عشان req.ip يبقى فعلاً IP بتاع الجهاز اللي بعت الطلب، مش IP البروكسي نفسه -
// ده مهم عشان حماية محاولات تسجيل الدخول المتكررة (تحت) تشتغل صح.
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// مسار قاعدة البيانات: تقدر تحدده عن طريق متغير بيئة KODAK_DB_PATH (مفيد لو
// عندك "قرص دائم" (Persistent Disk) في خدمة الاستضافة، عشان بياناتك تفضل
// موجودة حتى لو السيرفر اتعمله إعادة تشغيل أو تحديث). لو مش محدد، بيستخدم
// المسار الافتراضي جنب server.js زي ما كان.
const dbPath = process.env.KODAK_DB_PATH || path.join(__dirname, 'kodak-pixel.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// السيرفر ده بيقدّم واجهة الكاشير (الفرونت إند) هو نفسه، عشان الموقع كله يبقى
// "حاجة واحدة" على رابط واحد: تكتب عنوان السيرفر في المتصفح، وتلاقي الكاشير
// شغال على طول، من غير ما تحتاج تفتح ملف الواجهة منفصل. لو عايز تحط الفرونت
// إند مكان تاني، غيّر المسار ده بس.
const FRONTEND_DIR = process.env.KODAK_FRONTEND_DIR || path.join(__dirname, '..', 'frontend');
app.use(express.static(FRONTEND_DIR));

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

// ============ إنشاء الجداول ============
db.exec(`
CREATE TABLE IF NOT EXISTS branches (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  address TEXT,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT,
  price REAL NOT NULL,
  branch_id TEXT,
  stock_qty REAL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  invoice_number INTEGER,
  branch_id TEXT,
  customer_name TEXT,
  customer_phone TEXT,
  items_json TEXT NOT NULL,
  discount_percent REAL DEFAULT 0,
  vat_percent REAL DEFAULT 0,
  vat_amount REAL DEFAULT 0,
  total_cost REAL NOT NULL,
  paid REAL DEFAULT 0,
  remaining REAL DEFAULT 0,
  pay_method TEXT,
  status TEXT DEFAULT 'not Delivered',
  created_by TEXT,
  shift_id TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS employees_attendance (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  employee_name TEXT,
  check_in INTEGER,
  check_out INTEGER,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS investments (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  investor_name TEXT,
  amount REAL NOT NULL,
  note TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'cashier',
  branch_id TEXT,
  monthly_salary REAL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS shifts (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  user_id TEXT,
  user_name TEXT,
  opened_at INTEGER NOT NULL,
  closed_at INTEGER,
  status TEXT DEFAULT 'open',
  summary_json TEXT,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  shift_id TEXT,
  description TEXT,
  amount REAL NOT NULL,
  category TEXT,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS advances (
  id TEXT PRIMARY KEY,
  branch_id TEXT,
  shift_id TEXT,
  employee_id TEXT,
  employee_name TEXT,
  amount REAL NOT NULL,
  note TEXT,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  settled INTEGER DEFAULT 0,
  settled_at INTEGER,
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
  amount REAL NOT NULL,
  method TEXT,
  note TEXT,
  created_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER DEFAULT 0
);
`);

// فرض تفرّد اسم الدخول عبر كل الفروع (Fix A).
// بنستخدم index لوحده بدل تعديل تعريف الجدول، عشان ده بيشتغل حتى لو الجدول
// كان اتعمل قبل كده من نسخة سابقة (CREATE TABLE IF NOT EXISTS مش بيغيّر أعمدة موجودة).
try {
  db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);`);
} catch (err) {
  console.warn('⚠️  تعذر فرض تفرّد اسم الدخول - على الأغلب فيه أسماء مكررة موجودة بالفعل:', err.message);
}

// ترقية قواعد بيانات قديمة اتعملت قبل إضافة الأعمدة دي (CREATE TABLE IF NOT EXISTS
// مابيضفش أعمدة لجدول موجود بالفعل). كل ALTER TABLE هنا محاط بـ try/catch عشان
// لو العمود موجود بالفعل (سيرفر جديد اتعمل بالسكيما الكاملة من الأول) نتجاهل
// الخطأ من غير ما نوقف تشغيل السيرفر.
const MIGRATIONS = [
  `ALTER TABLE users ADD COLUMN monthly_salary REAL DEFAULT 0;`,
  `ALTER TABLE advances ADD COLUMN employee_id TEXT;`,
  `ALTER TABLE advances ADD COLUMN settled INTEGER DEFAULT 0;`,
  `ALTER TABLE advances ADD COLUMN settled_at INTEGER;`,
  `ALTER TABLE invoices ADD COLUMN vat_percent REAL DEFAULT 0;`,
  `ALTER TABLE invoices ADD COLUMN vat_amount REAL DEFAULT 0;`,
];
for (const sql of MIGRATIONS) {
  try { db.exec(sql); } catch (err) { /* العمود موجود بالفعل غالباً، تجاهل */ }
}

// ============ منطق المزامنة (Sync Engine) ============
// المبدأ: كل صف عنده updated_at (وقت التعديل بالميلي ثانية).
// لما تيجي نسخة من العميل، لو وقتها أحدث من اللي في السيرفر (أو مش موجودة أصلاً) بنحدّثها.
// ده بيحل تعارض التعديلات لو حصل تعديل من فرعين في نفس الوقت (آخر تعديل بيكسب).

// بيضمن إن كل الأعمدة المطلوبة موجودة في الصف قبل ما نحاول نحفظه، حتى لو
// الصف جاي من نسخة قديمة من الواجهة (قبل إضافة عمود جديد زي employee_id أو
// monthly_salary) وبالتالي الخاصية دي مش موجودة في الأوبجكت خالص - بنحطها null
// بدل ما نخلي better-sqlite3 يرمي خطأ "missing named parameter".
function normalizeRow(row, columns) {
  const out = {};
  for (const c of columns) out[c] = row[c] === undefined ? null : row[c];
  return out;
}

function upsertRows(table, rows, columns) {
  if (!rows || rows.length === 0) return;
  const placeholders = columns.map(c => `@${c}`).join(', ');
  const updateSet = columns.filter(c => c !== 'id').map(c => `${c}=excluded.${c}`).join(', ');
  const stmt = db.prepare(`
    INSERT INTO ${table} (${columns.join(', ')})
    VALUES (${placeholders})
    ON CONFLICT(id) DO UPDATE SET ${updateSet}
    WHERE excluded.updated_at > ${table}.updated_at
  `);
  const insertMany = db.transaction((items) => {
    for (const item of items) stmt.run(normalizeRow(item, columns));
  });
  insertMany(rows);
}

// معالجة خاصة لجدول المستخدمين: لو حصل تعارض في اسم الدخول (مثلاً فرعين
// أنشأوا يوزر بنفس الاسم أوفلاين)، بنتجاهل السطر ده بس من غير ما نوقف باقي المزامنة.
function upsertUsers(rows) {
  if (!rows || rows.length === 0) return { skipped: [] };
  const columns = TABLE_SCHEMAS.users;
  const placeholders = columns.map(c => `@${c}`).join(', ');
  const updateSet = columns.filter(c => c !== 'id').map(c => `${c}=excluded.${c}`).join(', ');
  const stmt = db.prepare(`
    INSERT INTO users (${columns.join(', ')})
    VALUES (${placeholders})
    ON CONFLICT(id) DO UPDATE SET ${updateSet}
    WHERE excluded.updated_at > users.updated_at
  `);
  const skipped = [];
  const insertMany = db.transaction((items) => {
    for (const item of items) {
      try {
        stmt.run(normalizeRow(item, columns));
      } catch (err) {
        if (err.message && err.message.includes('UNIQUE constraint failed: users.username')) {
          console.warn(`⚠️  تم تجاهل تعارض اسم الدخول أثناء المزامنة: user ${item.id} (${item.username})`);
          skipped.push({ id: item.id, username: item.username });
          continue; // نكمل باقي السطور بدل ما نفشل المزامنة كلها
        }
        throw err; // أي خطأ تاني (مش تعارض اسم الدخول) لازم يفضل يظهر
      }
    }
  });
  insertMany(rows);
  return { skipped };
}

// جلب أي صفوف اتحدثت بعد وقت معين (عشان نبعتها للعميل)
function getUpdatedSince(table, since) {
  return db.prepare(`SELECT * FROM ${table} WHERE updated_at > ?`).all(since || 0);
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

app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'اكتب اسم الدخول وكلمة المرور' });
    }
    const rlKey = loginRateLimitKey(req, username);
    if (isRateLimited(rlKey)) {
      return res.status(429).json({ error: 'محاولات كتير غلط، حاول تاني بعد شوية' });
    }
    const user = db.prepare('SELECT * FROM users WHERE username = ? AND deleted = 0').get(username);
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
// لو الطلب من غير توكن أصلاً (جهاز أقدم أو أوفلاين وقت أول تسجيل دخول) بنكمل
// عادي زي قبل، عشان منكسرش النظام الحالي.
const ADMIN_ONLY_TABLES = new Set(['users', 'branches', 'products']);

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
function serverHasAnyUser() {
  const row = db.prepare('SELECT COUNT(*) as c FROM users WHERE deleted = 0').get();
  return row.c > 0;
}

function requireAuthUnlessBootstrapping(req, res, next) {
  if (req.user) return next(); // توكن صالح، اتفضل
  if (!serverHasAnyUser()) return next(); // قاعدة بيانات فاضية تماماً - أول تشغيل، مسموح
  return res.status(401).json({ error: 'unauthorized', message: 'لازم تسجّل الدخول الأول عشان تقدر تزامن البيانات' });
}

app.post('/api/sync', optionalAuth, requireAuthUnlessBootstrapping, (req, res) => {
  try {
    const body = req.body || {};
    const since = body.since || 0;
    let skippedUsers = [];

    for (const table of Object.keys(TABLE_SCHEMAS)) {
      if (!Array.isArray(body[table])) continue;
      const allowedRows = filterRowsForRole(table, body[table], req.user);
      if (table === 'users') {
        const result = upsertUsers(allowedRows);
        skippedUsers = result.skipped;
      } else {
        upsertRows(table, allowedRows, TABLE_SCHEMAS[table]);
      }
    }

    const response = { serverTime: Date.now() };
    if (skippedUsers.length) response.skippedUsers = skippedUsers;
    for (const table of Object.keys(TABLE_SCHEMAS)) {
      response[table] = getUpdatedSince(table, since);
    }

    res.json(response);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'sync_failed', message: err.message });
  }
});

// نقطة لتحميل كل البيانات من الصفر (أول مرة يفتح فيها فرع جديد)
app.get('/api/full-state', optionalAuth, requireAuthUnlessBootstrapping, (req, res) => {
  const response = { serverTime: Date.now() };
  for (const table of Object.keys(TABLE_SCHEMAS)) {
    response[table] = db.prepare(`SELECT * FROM ${table} WHERE deleted = 0`).all();
  }
  res.json(response);
});

app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ سيرفر كوداك بيكسل شغال على المنفذ ${PORT}`);
});
