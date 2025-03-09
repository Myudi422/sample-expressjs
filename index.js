require("dotenv").config();
const mysql = require("mysql2/promise");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const multer  = require("multer");
const path = require("path");
const fs = require("fs");
const https = require("https");
const AWS = require("aws-sdk");

const express = require('express')
const app = express()
const port = process.env.PORT || 3000

app.use(cors()); // Mengizinkan semua domain
app.use(express.json());

// Konfigurasi AWS SDK untuk Backblaze B2
const s3 = new AWS.S3({
  endpoint: process.env.B2_ENDPOINT || "https://s3.us-east-005.backblazeb2.com",
  accessKeyId: process.env.B2_ACCESS_KEY,
  secretAccessKey: process.env.B2_SECRET_KEY,
  region: process.env.B2_REGION || "us-east-005",
  signatureVersion: "v4",
  s3ForcePathStyle: true,
});
const BUCKET_NAME = process.env.B2_BUCKET || "ccgnimex";

// Gunakan multer dengan memoryStorage agar file langsung diupload ke B2
const upload = multer({ storage: multer.memoryStorage() });

// Koneksi ke database
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Secret key untuk JWT
const JWT_SECRET = process.env.JWT_SECRET;
const domain = process.env.DOMAIN;

// Fungsi untuk menghasilkan slug unik
function generateUniqueSlug() {
  return Math.random().toString(36).substring(2, 15) + 
         Math.random().toString(36).substring(2, 15);
}

// Fungsi untuk menghasilkan token JWT
function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, name: user.name, profile_pictures: user.profile_pictures },
    JWT_SECRET,
    { expiresIn: "1h" }
  );
}

// Endpoint Auth
app.post("/api/auth", async (req, res) => {
  const { name, email } = req.body;
  try {
    const [rows] = await pool.execute("SELECT * FROM users_legal WHERE email = ?", [email]);
    let user;
    if (rows.length > 0) {
      await pool.execute(
        "UPDATE users_legal SET name = ?, updated_at = NOW() WHERE email = ?",
        [name, email]
      );
      user = rows[0];
    } else {
      const [result] = await pool.execute(
        "INSERT INTO users_legal (name, email, role, created_at, updated_at) VALUES (?, ?, 'user', NOW(), NOW())",
        [name, email]
      );
      user = { id: result.insertId, name, email, role: "user" };
    }

    if (req.body.profile_picture) {
      await pool.execute(
        "UPDATE users_legal SET profile_pictures = ? WHERE email = ?",
        [req.body.profile_picture, email]
      );
      user.profile_pictures = req.body.profile_picture;
    }

    const token = generateToken(user);
    res.status(200).json({ message: "Login berhasil.", token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Gagal menyimpan data pengguna." });
  }
});

// Middleware untuk verifikasi token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Akses ditolak. Token tidak ditemukan." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token tidak valid atau telah kedaluwarsa." });
    }
    req.user = user;
    next();
  });
}

app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Tidak ada file yang diupload' });
  }
  
  const file = req.file;
  const { slug, fieldName } = req.body; // Ambil slug dan fieldName dari request body

  if (!slug || !fieldName) {
    return res.status(400).json({ message: 'Slug dan fieldName harus disediakan' });
  }

  // Dapatkan ekstensi file (contoh: .jpg, .png)
  const extension = path.extname(file.originalname);
  // Buat path file sesuai format: dokasah/berkas/{slug}/{fieldName}{extension}
  const filePath = `dokasah/berkas/${slug}/${fieldName}${extension}`;

  try {
    const params = {
      Bucket: BUCKET_NAME,
      Key: filePath,
      Body: file.buffer,
      ContentType: file.mimetype,
    };

    const uploadResult = await s3.upload(params).promise();
    res.status(200).json({ message: 'File berhasil diupload', fileUrl: uploadResult.Location });
  } catch (err) {
    console.error('Error uploading file to B2', err);
    res.status(500).json({ message: 'Error uploading file to B2' });
  }
});


app.post('/api/upload-file', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'Tidak ada file yang diupload' });
  }
  
  const file = req.file;
  const { slug, fieldName } = req.body; // Ambil slug dan fieldName dari request body

  if (!slug || !fieldName) {
    return res.status(400).json({ message: 'Slug dan fieldName harus disediakan' });
  }

  // Dapatkan ekstensi file (contoh: .jpg, .png)
  const extension = path.extname(file.originalname);
  // Buat path file sesuai format: dokasah/berkas/{slug}/{fieldName}{extension}
  const filePath = `dokasah/berkas/${slug}/${fieldName}${extension}`;

  try {
    const params = {
      Bucket: BUCKET_NAME,
      Key: filePath,
      Body: file.buffer,
      ContentType: file.mimetype,
    };

    const uploadResult = await s3.upload(params).promise();
    res.status(200).json({ message: 'File berhasil diupload', fileUrl: uploadResult.Location });
  } catch (err) {
    console.error('Error uploading file to B2', err);
    res.status(500).json({ message: 'Error uploading file to B2' });
  }
});





// Contoh API yang dilindungi oleh token
app.get("/api/protected", authenticateToken, (req, res) => {
  res.status(200).json({ message: "Ini adalah data terlindungi.", user: req.user });
});

app.post('/api/forms', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Forbidden' });

  const { email, formType } = req.body; // Tidak perlu formStructure
  const slug = generateUniqueSlug();

  try {
    // Cek apakah form type valid
    const [formTypeCheck] = await pool.execute(
      'SELECT * FROM form_structures WHERE form_type = ?',
      [formType]
    );
    
    if (formTypeCheck.length === 0) {
      return res.status(400).json({ message: 'Jenis formulir tidak valid' });
    }

    // Insert ke form_configurations tanpa form_structure
    const [result] = await pool.execute(
      'INSERT INTO form_configurations (form_type, assigned_email, slug) VALUES (?, ?, ?)',
      [formType, email, slug]
    );

    // Akses DOMAIN dari .env
  const domain = process.env.DOMAIN;

  // Buat link dengan menggabungkan DOMAIN dan slug
  const link = `https://${domain}/form/${slug}`;

  // Kirim respons dengan status 201 dan link
  res.status(201).json({
    message: "Form created successfully",
    link: link,
  });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Gagal membuat form' });
  }
});

app.get('/files/*', async (req, res) => {
  try {
      res.setHeader('Content-Type', 'application/json');

      const folderPath = req.params[0]; // Tangkap path setelah /files/
      const prefix = folderPath.endsWith('/') ? folderPath : folderPath + '/'; // Pastikan ada '/' di akhir
      const CDN_URL = "https://file.ccgnimex.my.id/file/ccgnimex/"; // URL CDN

      // **1. Fetch dari S3 terlebih dahulu**
      const data = await s3.listObjectsV2({
          Bucket: BUCKET_NAME,
          Prefix: prefix
      }).promise();

      if (!data.Contents || data.Contents.length === 0) {
          return res.json({ files: [], folders: [] });
      }

      const folders = new Map(); // Menggunakan Map untuk menyimpan slug dan nama
      const files = [];
      const detectedSlugs = new Set();

      // **2. Identifikasi slug yang perlu dicari di database**
      data.Contents.forEach(file => {
          const relativePath = file.Key.replace(prefix, '');
          const parts = relativePath.split('/');

          if (parts.length > 1) {
              detectedSlugs.add(parts[0]); // Simpan slug yang ditemukan
              folders.set(parts[0], { slug: parts[0], name: parts[0] }); // Default slug = name
          }
      });

      // **3. Query database untuk slug yang ditemukan**
      if (detectedSlugs.size > 0) {
          const placeholders = Array.from(detectedSlugs).map(() => '?').join(',');
          const query = `SELECT slug, nama_folder FROM form_folder WHERE slug IN (${placeholders})`;
          const [rows] = await pool.execute(query, Array.from(detectedSlugs));

          rows.forEach(row => {
              if (folders.has(row.slug)) {
                  folders.set(row.slug, { slug: row.slug, name: row.nama_folder });
              }
          });
      }

      // **4. Proses ulang hasil dari S3**
      data.Contents.forEach(file => {
          let relativePath = file.Key.replace(prefix, '');
          let parts = relativePath.split('/');

          if (parts.length > 1) {
              folders.set(parts[0], folders.get(parts[0])); // Pastikan folder ada di Map
          } else {
              files.push({
                  key: relativePath,
                  lastModified: file.LastModified,
                  size: file.Size,
                  storageClass: file.StorageClass,
                  url: `${CDN_URL}${file.Key}`
              });
          }
      });

      res.json({ files, folders: Array.from(folders.values()) });

  } catch (err) {
      console.error('Error fetching folder contents:', err);
      res.status(500).json({ error: 'Error fetching folder contents' });
  }
});



  
app.get('/api/forms/:slug', authenticateToken, async (req, res) => {
  try {
    // Join dengan form_structures untuk ambil struktur
    const [forms] = await pool.execute(
      `SELECT fc.*, fs.form_structure 
       FROM form_configurations fc
       JOIN form_structures fs ON fc.form_type = fs.form_type
       WHERE slug = ?`,
      [req.params.slug]
    );

    if (forms.length === 0) return res.status(404).json({ message: 'Form tidak ditemukan' });

    const form = forms[0];
    // Izinkan akses jika user adalah pemilik atau admin
    if (form.assigned_email !== req.user.email && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Akses ditolak' });
    }

    // Ambil submission
    const [submissions] = await pool.execute(
      'SELECT * FROM form_submissions WHERE form_config_id = ? AND user_id = ?',
      [form.id, req.user.id]
    );

    res.json({
      form: {
        ...form,
        form_structure: form.form_structure // Ambil dari join
      },
      submission: submissions[0] || null
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


// Endpoint untuk mendapatkan count status formulir di dashboard
app.get('/api/dashboard/status-count', authenticateToken, async (req, res) => {
  try {
    // Hanya admin yang boleh mengakses endpoint ini. Jika perlu, sesuaikan sesuai kebijakan.
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Akses ditolak' });
    }
    
    const [rows] = await pool.execute(`
      SELECT 
        SUM(CASE WHEN fs.status IS NULL OR fs.status = 'draft' THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN fs.status = 'submitted' THEN 1 ELSE 0 END) AS selesai,
        SUM(CASE WHEN fs.status = 'proses' THEN 1 ELSE 0 END) AS proses,
        SUM(CASE WHEN fs.status = 'review' THEN 1 ELSE 0 END) AS review
      FROM form_configurations fc
      LEFT JOIN form_submissions fs ON fc.id = fs.form_config_id
    `);
    
    // rows[0] berisi objek dengan properti pending, selesai, proses, dan review
    res.status(200).json({ counts: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


  
  
  // Save draft
  app.put('/api/forms/:slug/draft', authenticateToken, async (req, res) => {
    try {
      const { slug } = req.params;
      const { data } = req.body;
  
      const [forms] = await pool.execute(
        'SELECT * FROM form_configurations WHERE slug = ?',
        [slug]
      );
  
      if (forms.length === 0) {
        return res.status(404).json({ message: 'Form not found' });
      }
  
      const form = forms[0];
  
      // Check email match
      if (form.assigned_email !== req.user.email) {
        return res.status(403).json({ message: 'Forbidden' });
      }
  
      // Check if submission exists
      const [submissions] = await pool.execute(
        'SELECT * FROM form_submissions WHERE form_config_id = ? AND user_id = ?',
        [form.id, req.user.id]
      );
  
      if (submissions.length > 0) {
        // Update existing draft
        await pool.execute(
          'UPDATE form_submissions SET data = ?, updated_at = NOW() WHERE id = ?',
          [JSON.stringify(data), submissions[0].id]
        );
      } else {
        // Create new draft
        await pool.execute(
          'INSERT INTO form_submissions (form_config_id, user_id, data) VALUES (?, ?, ?)',
          [form.id, req.user.id, JSON.stringify(data)]
        );
      }
  
      res.status(200).json({ message: 'Draft saved successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Failed to save draft' });
    }
  });
  
  // Submit form
  app.post('/api/forms/:slug/submit', authenticateToken, async (req, res) => {
    try {
      const { slug } = req.params;
      const { data } = req.body;
  
      const [forms] = await pool.execute(
        'SELECT * FROM form_configurations WHERE slug = ?',
        [slug]
      );
  
      if (forms.length === 0) {
        return res.status(404).json({ message: 'Form not found' });
      }
  
      const form = forms[0];
  
      // Check email match
      if (form.assigned_email !== req.user.email) {
        return res.status(403).json({ message: 'Forbidden' });
      }
  
      // Check if submission exists
      const [submissions] = await pool.execute(
        'SELECT * FROM form_submissions WHERE form_config_id = ? AND user_id = ?',
        [form.id, req.user.id]
      );
  
      if (submissions.length > 0) {
        // Update existing submission
        await pool.execute(
          'UPDATE form_submissions SET data = ?, status = "submitted", updated_at = NOW() WHERE id = ?',
          [JSON.stringify(data), submissions[0].id]
        );
      } else {
        // Create new submission
        await pool.execute(
          'INSERT INTO form_submissions (form_config_id, user_id, data, status) VALUES (?, ?, ?, "submitted")',
          [form.id, req.user.id, JSON.stringify(data)]
        );
      }
  
      res.status(200).json({ message: 'Form submitted successfully' });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Failed to submit form' });
    }
  });


// Endpoint untuk mengambil data form beserta status dan updated_at
app.get('/api/dashboard/forms', authenticateToken, async (req, res) => {
  try {
    let query, params;
    // Jika admin, tampilkan semua formulir
    if (req.user.role === 'admin') {
      query = `
        SELECT 
          fc.id, 
          fc.form_type, 
          fc.assigned_email, 
          fc.slug, 
          fs.status, 
          fs.updated_at 
        FROM form_configurations fc
        LEFT JOIN form_submissions fs ON fc.id = fs.form_config_id
        ORDER BY fs.updated_at DESC
      `;
      params = [];
    } else {
      // Jika bukan admin, tampilkan formulir berdasarkan email user
      query = `
        SELECT 
          fc.id, 
          fc.form_type, 
          fc.assigned_email, 
          fc.slug, 
          fs.status, 
          fs.updated_at 
        FROM form_configurations fc
        LEFT JOIN form_submissions fs ON fc.id = fs.form_config_id
        WHERE fc.assigned_email = ?
        ORDER BY fs.updated_at DESC
      `;
      params = [req.user.email];
    }
    
    const [rows] = await pool.execute(query, params);
    res.status(200).json({ forms: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});



  // PUT: Update submission status
// PUT: Update submission status
app.put('/api/forms/:slug/status', authenticateToken, async (req, res) => {
  try {
    const { slug } = req.params;
    const { status } = req.body;

    // Dapatkan form configuration
    const [forms] = await pool.execute(
      'SELECT * FROM form_configurations WHERE slug = ?',
      [slug]
    );
    
    if (forms.length === 0) {
      return res.status(404).json({ message: 'Form tidak ditemukan' });
    }

    const form = forms[0];

    // Validasi: jika bukan admin, pastikan email user cocok
    if (req.user.role !== 'admin' && form.assigned_email !== req.user.email) {
      return res.status(403).json({ message: 'Akses ditolak' });
    }

    if (req.user.role === 'admin') {
      // Untuk admin: update seluruh submission yang terkait dengan form ini
      const [result] = await pool.execute(
        'UPDATE form_submissions SET status = ?, updated_at = NOW() WHERE form_config_id = ?',
        [status, form.id]
      );
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: 'Submission tidak ditemukan' });
      }
    } else {
      // Untuk user biasa: update submission milik user
      const [submissions] = await pool.execute(
        'SELECT * FROM form_submissions WHERE form_config_id = ? AND user_id = ?',
        [form.id, req.user.id]
      );
      if (submissions.length === 0) {
        return res.status(404).json({ message: 'Submission tidak ditemukan' });
      }
      await pool.execute(
        'UPDATE form_submissions SET status = ?, updated_at = NOW() WHERE id = ?',
        [status, submissions[0].id]
      );
    }

    res.status(200).json({ message: 'Status berhasil diupdate' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Gagal mengupdate status' });
  }
});


// Jalankan server
app.listen(PORT, () => {
  console.log(`Backend berjalan di https://localhost:${PORT}`);
});
