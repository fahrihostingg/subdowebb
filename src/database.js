const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(__dirname, '../database.sqlite');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  // Jadual Pengguna
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'user', -- 'owner' | 'user'
      package TEXT DEFAULT 'biasa', -- 'biasa' (3) | 'prem' (6) | 'vip' (10)
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Jadual Domain Induk (Diuruskan oleh Owner)
  db.run(`
    CREATE TABLE IF NOT EXISTS domains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain_name TEXT UNIQUE NOT NULL, -- e.g. fakrulafif.store
      cf_zone_id TEXT NOT NULL,
      cf_api_token TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Jadual Subdomain
  db.run(`
    CREATE TABLE IF NOT EXISTS subdomains (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      domain_id INTEGER NOT NULL,
      parent_subdomain_id INTEGER NULL, -- NULL jika utama; ID induk jika sekunder
      full_domain TEXT UNIQUE NOT NULL, -- e.g. pahri.fakrulafif.store atau panel.pahri.fakrulafif.store
      prefix TEXT NOT NULL, -- e.g. pahri atau panel
      record_type TEXT NOT NULL, -- 'A' atau 'CNAME'
      target_value TEXT NOT NULL, -- IP atau Hostname
      cf_record_id TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id),
      FOREIGN KEY(domain_id) REFERENCES domains(id)
    )
  `);

  // Auto-create default Owner jika belum wujud
  const adminEmail = process.env.ADMIN_EMAIL || 'owner@fakrulafif.store';
  const adminPassword = process.env.ADMIN_PASSWORD || 'PasswordOwner123!';

  db.get('SELECT id FROM users WHERE email = ?', [adminEmail], (err, row) => {
    if (!row) {
      const hashed = bcrypt.hashSync(adminPassword, 10);
      db.run(
        'INSERT INTO users (email, password, role, package) VALUES (?, ?, ?, ?)',
        [adminEmail, hashed, 'owner', 'vip']
      );
      console.log(`[DB] Akaun Owner dicipta: ${adminEmail}`);
    }
  });
});

module.exports = db;
