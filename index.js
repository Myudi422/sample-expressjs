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

// Endpoint DELETE untuk menghapus formulir
app.delete('/api/forms/:slug', authenticateToken, async (req, res) => {
  try {
    const { slug } = req.params;

    // Hanya admin yang boleh menghapus
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Akses ditolak' });
    }

    // Mulai transaksi database
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // 1. Dapatkan data form configuration
      const [forms] = await connection.execute(
        'SELECT * FROM form_configurations WHERE slug = ?',
        [slug]
      );
      
      if (forms.length === 0) {
        return res.status(404).json({ message: 'Form tidak ditemukan' });
      }
      const form = forms[0];

      // 2. Hapus form_submissions terkait
      await connection.execute(
        'DELETE FROM form_submissions WHERE form_config_id = ?',
        [form.id]
      );

      // 3. Hapus form_configurations
      await connection.execute(
        'DELETE FROM form_configurations WHERE id = ?',
        [form.id]
      );

      // 4. Hapus folder di Backblaze
      const folderPath = `dokasah/berkas/${slug}/`;
      const listParams = {
        Bucket: BUCKET_NAME,
        Prefix: folderPath
      };
      
      const listedObjects = await s3.listObjectsV2(listParams).promise();
      
      if (listedObjects.Contents.length > 0) {
        const deleteParams = {
          Bucket: BUCKET_NAME,
          Delete: { Objects: listedObjects.Contents.map(({ Key }) => ({ Key })) }
        };
        await s3.deleteObjects(deleteParams).promise();
      }

      // Hapus folder itu sendiri (jika kosong)
      await s3.deleteObject({
        Bucket: BUCKET_NAME,
        Key: folderPath
      }).promise();

      // Commit transaksi
      await connection.commit();
      res.status(200).json({ message: 'Formulir berhasil dihapus' });
    } catch (err) {
      // Rollback transaksi jika ada error
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (err) {
    console.error('Error menghapus formulir:', err);
    res.status(500).json({ message: 'Gagal menghapus formulir' });
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

app.get('/files/*', authenticateToken, async (req, res) => {
  try {
    res.setHeader('Content-Type', 'application/json');

    const folderPath = req.params[0]; // Tangkap path setelah /files/
    const prefix = folderPath.endsWith('/') ? folderPath : folderPath + '/'; // Pastikan ada '/' di akhir
    const CDN_URL = "https://file.ccgnimex.my.id/file/ccgnimex/";

    // **1. Fetch dari S3 terlebih dahulu**
    const data = await s3.listObjectsV2({
      Bucket: BUCKET_NAME,
      Prefix: prefix
    }).promise();

    if (!data.Contents || data.Contents.length === 0) {
      return res.json({ files: [], folders: [] });
    }

    // **2. Jika bukan admin, ambil daftar slug yang diizinkan dari DB**
    let allowedSlugs = [];
    if (req.user.role !== 'admin') {
      const [allowedRows] = await pool.execute(
        'SELECT slug FROM form_configurations WHERE assigned_email = ?',
        [req.user.email]
      );
      allowedSlugs = allowedRows.map(row => row.slug);
    }

    const folders = new Map(); // Untuk menyimpan folder dengan format { slug, name }
    const files = [];

    // **3. Proses hasil dari S3 dan filter folder sesuai allowedSlugs**
    data.Contents.forEach(file => {
      const relativePath = file.Key.replace(prefix, '');
      const parts = relativePath.split('/');

      // Jika file berada di dalam folder
      if (parts.length > 1) {
        const folderSlug = parts[0];
        // Jika bukan admin dan folderSlug tidak ada di allowedSlugs, lewati
        if (req.user.role !== 'admin' && !allowedSlugs.includes(folderSlug)) {
          return;
        }
        // Set folder default (nama sama dengan slug)
        folders.set(folderSlug, { slug: folderSlug, name: folderSlug });
      } else {
        // File yang berada di root
        files.push({
          key: relativePath,
          lastModified: file.LastModified,
          size: file.Size,
          storageClass: file.StorageClass,
          url: `${CDN_URL}${file.Key}`
        });
      }
    });

    // **4. Query database untuk update nama folder jika ada di tabel form_folder**
    if (folders.size > 0) {
      const detectedSlugs = Array.from(folders.keys());
      const placeholders = detectedSlugs.map(() => '?').join(',');
      const query = `SELECT slug, nama_folder FROM form_folder WHERE slug IN (${placeholders})`;
      const [rows] = await pool.execute(query, detectedSlugs);

      rows.forEach(row => {
        if (folders.has(row.slug)) {
          folders.set(row.slug, { slug: row.slug, name: row.nama_folder });
        }
      });
    }

    res.json({ files, folders: Array.from(folders.values()) });
  } catch (err) {
    console.error('Error fetching folder contents:', err);
    res.status(500).json({ error: 'Error fetching folder contents' });
  }
});


app.post('/api/rename', authenticateToken, async (req, res) => {
  try {
    // Hanya admin yang boleh mengakses endpoint ini
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Akses ditolak. Hanya admin yang dapat melakukan rename folder.' });
    }

    const { slug, name } = req.body;
    
    // Validasi input
    if (!slug || !name) {
      return res.status(400).json({ message: 'Slug dan name harus disediakan' });
    }
    
    // Cek apakah data untuk slug tersebut sudah ada di tabel form_folder
    const [rows] = await pool.execute(
      'SELECT * FROM form_folder WHERE slug = ?',
      [slug]
    );
    
    if (rows.length === 0) {
      // Jika belum ada, ambil id_form dari tabel form_configurations berdasarkan slug
      const [fcRows] = await pool.execute(
        'SELECT id FROM form_configurations WHERE slug = ?',
        [slug]
      );
      
      if (fcRows.length === 0) {
        return res.status(400).json({ message: 'Form configuration tidak ditemukan untuk slug tersebut' });
      }
      
      const id_form = fcRows[0].id;
      
      // Insert data baru ke form_folder dengan id_form, slug, dan nama_folder
      await pool.execute(
        'INSERT INTO form_folder (id_form, slug, nama_folder) VALUES (?, ?, ?)',
        [id_form, slug, name]
      );
      return res.status(201).json({ message: 'Nama folder berhasil dibuat' });
    } else {
      // Jika sudah ada, update nama folder
      await pool.execute(
        'UPDATE form_folder SET nama_folder = ? WHERE slug = ?',
        [name, slug]
      );
      return res.status(200).json({ message: 'Nama folder berhasil diperbarui' });
    }
  } catch (err) {
    console.error('Error pada /api/rename:', err);
    res.status(500).json({ message: 'Terjadi kesalahan pada server' });
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

    if (forms.length === 0)
      return res.status(404).json({ message: 'Form tidak ditemukan' });

    const form = forms[0];
    // Jika bukan admin, izinkan akses hanya jika user adalah pemilik form (assigned_email)
    if (req.user.role !== 'admin' && form.assigned_email !== req.user.email) {
      return res.status(403).json({ message: 'Akses ditolak' });
    }

    // Tentukan target user id untuk mengambil submission
    let targetUserId = req.user.id;
    if (req.user.role === 'admin') {
      // Cari id user dari tabel users_legal berdasarkan assigned_email
      const [userRows] = await pool.execute(
        'SELECT id FROM users_legal WHERE email = ?',
        [form.assigned_email]
      );
      if (userRows.length > 0) {
        targetUserId = userRows[0].id;
      }
    }

    // Ambil submission berdasarkan form.id dan targetUserId
    const [submissions] = await pool.execute(
      'SELECT * FROM form_submissions WHERE form_config_id = ? AND user_id = ?',
      [form.id, targetUserId]
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

    // Jika bukan admin, cek apakah email pemilik form cocok dengan user
    if (req.user.role !== 'admin' && form.assigned_email !== req.user.email) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    // Tentukan target user id: jika admin, gunakan id user dari assigned_email, jika tidak, gunakan req.user.id
    let targetUserId = req.user.id;
    if (req.user.role === 'admin') {
      const [userRows] = await pool.execute(
        'SELECT id FROM users_legal WHERE email = ?',
        [form.assigned_email]
      );
      if (userRows.length > 0) {
        targetUserId = userRows[0].id;
      }
    }

    // Cek apakah submission sudah ada untuk form ini dan target user
    const [submissions] = await pool.execute(
      'SELECT * FROM form_submissions WHERE form_config_id = ? AND user_id = ?',
      [form.id, targetUserId]
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
        [form.id, targetUserId, JSON.stringify(data)]
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

app.get('/api/blog/:slug', async (req, res) => {
  try {
    const { slug } = req.params;
    const [articles] = await pool.execute('SELECT * FROM blog WHERE slug = ?', [slug]);

    if (articles.length === 0) {
      return res.status(404).json({ message: "Article not found" });
    }

    const article = articles[0];

    // Ambil gambar berdasarkan blog_id
    const [images] = await pool.execute('SELECT id, image_url FROM blog_images WHERE blog_id = ?', [article.id]);

    // Kembalikan data artikel dan gambar
    res.status(200).json({ ...article, images });
  } catch (error) {
    console.error("Error fetching blog article:", error);
    res.status(500).json({ message: "Server error" });
  }
});


// Endpoint GET untuk mengambil semua artikel blog
app.get('/api/blog', async (req, res) => {
  try {
    // Query untuk mengambil id, title, slug, dan image utama dari tabel blog
    const [rows] = await pool.execute(
      'SELECT id, title, slug, image FROM blog ORDER BY created_at DESC'
    );
    res.status(200).json(rows);
  } catch (error) {
    console.error('Error fetching blog posts:', error);
    res.status(500).json({ message: 'Server error' });
  }
});



// Jalankan server
app.listen(port, () => {
  console.log(`Backend berjalan di https://localhost:${port}`);
});
