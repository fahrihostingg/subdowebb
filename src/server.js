require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./database');
const { createDnsRecord, deleteDnsRecord } = require('./cloudflare');

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'rahsia-vps-subdomain-12345',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
  })
);

const PACKAGE_LIMITS = {
  biasa: 3,
  prem: 6,
  vip: 10
};

function authRequired(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function ownerOnly(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'owner') {
    return res.status(403).send('Akses Ditolak: Khas untuk Owner sahaja.');
  }
  next();
}

// ---------------- ROUTES ---------------- //

// Laman Utama: Pendaftaran Subdomain Utama & Akaun Baru
app.get('/', (req, res) => {
  db.all('SELECT id, domain_name FROM domains', [], (err, domains) => {
    res.render('register', { domains: domains || [], error: null, success: null });
  });
});

app.post('/register', async (req, res) => {
  const { email, password, confirm_password, prefix, domain_id, record_type, target_value } = req.body;

  db.all('SELECT id, domain_name FROM domains', [], async (err, domains) => {
    if (!email || !password || !confirm_password || !prefix || !domain_id || !target_value) {
      return res.render('register', { domains, error: 'Sila lengkapkan semua ruangan!', success: null });
    }

    if (password !== confirm_password) {
      return res.render('register', { domains, error: 'Kata laluan dan pengesahan kata laluan tidak sepadan!', success: null });
    }

    const cleanPrefix = prefix.toLowerCase().replace(/[^a-z0-9-]/g, '');
    if (!cleanPrefix) {
      return res.render('register', { domains, error: 'Format nama subdomain tidak sah!', success: null });
    }

    db.get('SELECT * FROM domains WHERE id = ?', [domain_id], async (err, domain) => {
      if (!domain) {
        return res.render('register', { domains, error: 'Domain induk tidak sah.', success: null });
      }

      const fullSubdomain = `${cleanPrefix}.${domain.domain_name}`;

      db.get('SELECT id FROM subdomains WHERE full_domain = ?', [fullSubdomain], async (err, existingSub) => {
        if (existingSub) {
          return res.render('register', { domains, error: `Subdomain ${fullSubdomain} telah wujud! Sila pilih nama lain.`, success: null });
        }

        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, existingUser) => {
          let user = existingUser;

          if (!user) {
            const hashedPassword = bcrypt.hashSync(password, 10);
            const insertUser = await new Promise((resolve, reject) => {
              db.run(
                'INSERT INTO users (email, password, role, package) VALUES (?, ?, ?, ?)',
                [email, hashedPassword, 'user', 'biasa'],
                function (insErr) {
                  if (insErr) return reject(insErr);
                  resolve(this.lastID);
                }
              );
            });
            user = { id: insertUser, email, role: 'user', package: 'biasa' };
          } else {
            if (!bcrypt.compareSync(password, user.password)) {
              return res.render('register', { domains, error: 'Email telah wujud tetapi kata laluan salah!', success: null });
            }

            const currentCount = await new Promise((resolve) => {
              db.get(
                'SELECT COUNT(*) as cnt FROM subdomains WHERE user_id = ? AND parent_subdomain_id IS NULL',
                [user.id],
                (cErr, row) => resolve(row ? row.cnt : 0)
              );
            });

            const maxLimit = user.role === 'owner' ? Infinity : PACKAGE_LIMITS[user.package] || 3;
            if (currentCount >= maxLimit) {
              return res.render('register', {
                domains,
                error: `Kuota penuh! Pakej anda (${user.package.toUpperCase()}) hanya dibenarkan maksimum ${maxLimit} subdomain utama.`,
                success: null
              });
            }
          }

          const cfResult = await createDnsRecord({
            zoneId: domain.cf_zone_id,
            apiToken: domain.cf_api_token,
            name: fullSubdomain,
            type: record_type,
            content: target_value,
            proxied: false
          });

          if (!cfResult.success) {
            return res.render('register', { domains, error: `Cloudflare Error: ${cfResult.error}`, success: null });
          }

          db.run(
            `INSERT INTO subdomains (user_id, domain_id, parent_subdomain_id, full_domain, prefix, record_type, target_value, cf_record_id)
             VALUES (?, ?, NULL, ?, ?, ?, ?, ?)`,
            [user.id, domain.id, fullSubdomain, cleanPrefix, record_type, target_value, cfResult.record.id],
            (dbErr) => {
              if (dbErr) {
                return res.render('register', { domains, error: `Ralat Pangkalan Data: ${dbErr.message}`, success: null });
              }

              req.session.user = { id: user.id, email: user.email, role: user.role, package: user.package };
              res.redirect('/dashboard');
            }
          );
        });
      });
    });
  });
});

// Login & Logout
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.render('login', { error: 'Email atau kata laluan tidak sah.' });
    }
    req.session.user = { id: user.id, email: user.email, role: user.role, package: user.package };
    res.redirect('/dashboard');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Dashboard Pengguna
app.get('/dashboard', authRequired, (req, res) => {
  const userId = req.session.user.id;

  db.get('SELECT * FROM users WHERE id = ?', [userId], (err, user) => {
    req.session.user = user;

    db.all(
      `SELECT s.*, d.domain_name 
       FROM subdomains s 
       JOIN domains d ON s.domain_id = d.id 
       WHERE s.user_id = ? AND s.parent_subdomain_id IS NULL`,
      [userId],
      (err, primarySubdomains) => {
        db.all(
          `SELECT s.*, p.full_domain as parent_domain
           FROM subdomains s
           JOIN subdomains p ON s.parent_subdomain_id = p.id
           WHERE s.user_id = ?`,
          [userId],
          (err, childSubdomains) => {
            const limit = user.role === 'owner' ? 'Unlimited' : (PACKAGE_LIMITS[user.package] || 3);
            res.render('dashboard', {
              user,
              primarySubdomains: primarySubdomains || [],
              childSubdomains: childSubdomains || [],
              limit,
              error: req.query.error || null,
              success: req.query.success || null
            });
          }
        );
      }
    );
  });
});

app.post('/subdomain/create-child', authRequired, async (req, res) => {
  const userId = req.session.user.id;
  const { parent_subdomain_id, child_prefix, record_type, target_value } = req.body;

  if (!parent_subdomain_id || !child_prefix || !target_value) {
    return res.redirect('/dashboard?error=Semua ruangan wajib diisi!');
  }

  const cleanPrefix = child_prefix.toLowerCase().replace(/[^a-z0-9-]/g, '');

  db.get(
    `SELECT s.*, d.cf_zone_id, d.cf_api_token, d.id as domain_id 
     FROM subdomains s 
     JOIN domains d ON s.domain_id = d.id 
     WHERE s.id = ? AND s.user_id = ? AND s.parent_subdomain_id IS NULL`,
    [parent_subdomain_id, userId],
    async (err, parent) => {
      if (!parent) {
        return res.redirect('/dashboard?error=Subdomain induk tidak sah atau bukan milik anda.');
      }

      const fullChildDomain = `${cleanPrefix}.${parent.full_domain}`;

      db.get('SELECT id FROM subdomains WHERE full_domain = ?', [fullChildDomain], async (err, exist) => {
        if (exist) {
          return res.redirect('/dashboard?error=Subdomain tersebut sudah wujud!');
        }

        const cfRes = await createDnsRecord({
          zoneId: parent.cf_zone_id,
          apiToken: parent.cf_api_token,
          name: fullChildDomain,
          type: record_type,
          content: target_value,
          proxied: false
        });

        if (!cfRes.success) {
          return res.redirect(`/dashboard?error=Cloudflare Error: ${encodeURIComponent(cfRes.error)}`);
        }

        db.run(
          `INSERT INTO subdomains (user_id, domain_id, parent_subdomain_id, full_domain, prefix, record_type, target_value, cf_record_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [userId, parent.domain_id, parent.id, fullChildDomain, cleanPrefix, record_type, target_value, cfRes.record.id],
          (dbErr) => {
            if (dbErr) {
              return res.redirect(`/dashboard?error=${encodeURIComponent(dbErr.message)}`);
            }
            res.redirect('/dashboard?success=Subdomain sekunder berjaya dicipta!');
          }
        );
      });
    }
  );
});

app.post('/subdomain/delete/:id', authRequired, (req, res) => {
  const subId = req.params.id;
  const userId = req.session.user.id;
  const isOwner = req.session.user.role === 'owner';

  const query = isOwner
    ? `SELECT s.*, d.cf_zone_id, d.cf_api_token FROM subdomains s JOIN domains d ON s.domain_id = d.id WHERE s.id = ?`
    : `SELECT s.*, d.cf_zone_id, d.cf_api_token FROM subdomains s JOIN domains d ON s.domain_id = d.id WHERE s.id = ? AND s.user_id = ?`;

  const params = isOwner ? [subId] : [subId, userId];

  db.get(query, params, async (err, sub) => {
    if (!sub) return res.redirect('/dashboard?error=Subdomain tidak dijumpai.');

    await deleteDnsRecord({
      zoneId: sub.cf_zone_id,
      apiToken: sub.cf_api_token,
      recordId: sub.cf_record_id
    });

    db.all('SELECT * FROM subdomains WHERE parent_subdomain_id = ?', [sub.id], async (cErr, children) => {
      if (children && children.length > 0) {
        for (const child of children) {
          await deleteDnsRecord({
            zoneId: sub.cf_zone_id,
            apiToken: sub.cf_api_token,
            recordId: child.cf_record_id
          });
        }
        db.run('DELETE FROM subdomains WHERE parent_subdomain_id = ?', [sub.id]);
      }

      db.run('DELETE FROM subdomains WHERE id = ?', [sub.id], () => {
        res.redirect('/dashboard?success=Subdomain berjaya dipadam.');
      });
    });
  });
});

// ---------------- OWNER ROUTES ---------------- //

app.get('/admin', authRequired, ownerOnly, (req, res) => {
  db.all('SELECT * FROM domains', [], (err, domains) => {
    db.all('SELECT id, email, role, package, created_at FROM users', [], (uErr, users) => {
      db.all(
        `SELECT s.*, u.email as owner_email 
         FROM subdomains s 
         JOIN users u ON s.user_id = u.id`,
        [],
        (sErr, allSubdomains) => {
          res.render('admin', {
            domains: domains || [],
            users: users || [],
            subdomains: allSubdomains || [],
            error: req.query.error || null,
            success: req.query.success || null
          });
        }
      );
    });
  });
});

app.post('/admin/domain/add', authRequired, ownerOnly, (req, res) => {
  const { domain_name, cf_zone_id, cf_api_token } = req.body;

  if (!domain_name || !cf_zone_id || !cf_api_token) {
    return res.redirect('/admin?error=Semua maklumat domain wajib diisi!');
  }

  const cleanDomain = domain_name.trim().toLowerCase();

  db.run(
    'INSERT INTO domains (domain_name, cf_zone_id, cf_api_token) VALUES (?, ?, ?)',
    [cleanDomain, cf_zone_id.trim(), cf_api_token.trim()],
    (err) => {
      if (err) {
        return res.redirect(`/admin?error=${encodeURIComponent(err.message)}`);
      }
      res.redirect('/admin?success=Domain baru berjaya ditambah!');
    }
  );
});

app.post('/admin/domain/delete/:id', authRequired, ownerOnly, (req, res) => {
  db.run('DELETE FROM domains WHERE id = ?', [req.params.id], () => {
    res.redirect('/admin?success=Domain berjaya dipadam.');
  });
});

app.post('/admin/user/update-package', authRequired, ownerOnly, (req, res) => {
  const { user_id, package_name, role } = req.body;
  db.run(
    'UPDATE users SET package = ?, role = ? WHERE id = ?',
    [package_name, role, user_id],
    () => {
      res.redirect('/admin?success=Maklumat pengguna berjaya dikemaskini!');
    }
  );
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[SERVER] Sistem Subdomain aktif di http://localhost:${PORT}`);
});
