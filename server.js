require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(cors());

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// ================= EMAIL =================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function emailTemplate(codigo) {
  return `
  <div style="background:#0b0f1a;padding:40px;font-family:Arial;color:#fff">
    <div style="max-width:500px;margin:auto;background:#111827;padding:30px;border-radius:12px;border:1px solid #1f2937">
      <h2 style="color:#00d4ff;text-align:center;">🔐 Stark Elite Pay</h2>
      <p style="text-align:center;">Seu código de verificação:</p>
      <div style="text-align:center;font-size:32px;color:#00d4ff;margin:20px 0;font-weight:bold;">
        ${codigo}
      </div>
      <p style="text-align:center;font-size:12px;">Código válido por poucos minutos</p>
    </div>
  </div>`;
}

// ================= BANCO =================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================= AUTH =================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.sendStatus(401);
  }
}

// ================= SETUP =================
app.get("/setup", async (req, res) => {
  await pool.query(`
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS pedidos;
    DROP TABLE IF EXISTS extrato;
    DROP TABLE IF EXISTS ganhos;

    CREATE TABLE users (
      id SERIAL PRIMARY KEY,
      nome TEXT,
      email TEXT UNIQUE,
      senha TEXT,
      cpf TEXT,
      codigo TEXT,
      verificado BOOLEAN DEFAULT false,
      saldo FLOAT DEFAULT 0
    );

    CREATE TABLE pedidos (
      id TEXT PRIMARY KEY,
      userid INT,
      valor FLOAT,
      status TEXT
    );

    CREATE TABLE extrato (
      id SERIAL PRIMARY KEY,
      userid INT,
      tipo TEXT,
      valor FLOAT,
      descricao TEXT,
      data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE ganhos (
      id SERIAL PRIMARY KEY,
      valor FLOAT,
      userid INT,
      pedidoid TEXT,
      data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  res.send("Banco pronto 🚀");
});

// ================= REGISTER =================
app.post("/register", async (req, res) => {
  try {
    const { nome, email, senha, confirmarSenha, cpf } = req.body;

    if (!nome || !email || !senha || !confirmarSenha || !cpf)
      return res.status(400).json({ erro: "Preencha todos os campos" });

    if (senha !== confirmarSenha)
      return res.status(400).json({ erro: "Senhas não conferem" });

    const hash = await bcrypt.hash(senha, 12);
    const codigo = Math.floor(100000 + Math.random() * 900000).toString();

    await pool.query(
      "INSERT INTO users (nome,email,senha,cpf,codigo) VALUES ($1,$2,$3,$4,$5)",
      [nome, email, hash, cpf, codigo]
    );

    await transporter.sendMail({
      to: email,
      subject: "🔐 Código Stark Elite Pay",
      html: emailTemplate(codigo)
    });

    res.json({ message: "Código enviado" });

  } catch (err) {
    res.status(500).json({ erro: "Erro" });
  }
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows[0]) return res.status(400).json({ erro: "Usuário não existe" });

  const ok = await bcrypt.compare(senha, user.rows[0].senha);
  if (!ok) return res.status(400).json({ erro: "Senha inválida" });

  const codigo = Math.floor(100000 + Math.random() * 900000).toString();

  await pool.query("UPDATE users SET codigo=$1 WHERE email=$2", [codigo, email]);

  await transporter.sendMail({
    to: email,
    subject: "🔑 Código de login",
    html: emailTemplate(codigo)
  });

  res.json({ message: "Código enviado" });
});

// ================= VERIFY LOGIN =================
app.post("/verify-login", async (req, res) => {
  const { email, codigo } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows[0] || user.rows[0].codigo !== codigo)
    return res.status(400).json({ erro: "Código inválido" });

  const token = jwt.sign({ id: user.rows[0].id }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ token });
});

// ================= SALDO =================
app.get("/saldo", auth, async (req, res) => {
  const result = await pool.query("SELECT saldo FROM users WHERE id=$1", [req.userId]);
  res.json(result.rows[0]);
});

// ================= EXTRATO =================
app.get("/extrato", auth, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM extrato WHERE userid=$1 ORDER BY data DESC",
    [req.userId]
  );
  res.json(result.rows);
});

// ================= PIX =================
app.post("/pix", auth, async (req, res) => {
  try {
    const { valor } = req.body;

    const id = Date.now().toString();

    await pool.query(
      "INSERT INTO pedidos (id, userid, valor, status) VALUES ($1,$2,$3,$4)",
      [id, req.userId, valor, "pending"]
    );

    const response = await axios.post(
      "https://api.elitepaybr.com/api/v1/deposit",
      {
        amount: valor,
        external_id: id
      },
      {
        headers: {
          "x-client-id": process.env.ELITEPAY_CLIENT_ID,
          "x-client-secret": process.env.ELITEPAY_CLIENT_SECRET
        }
      }
    );

    const data = response.data;

    res.json({
      valor,
      qrCode: data.qr_code || data.qrcode,
      pixCopiaECola: data.pix_code || data.payload
    });

  } catch (err) {
    res.status(500).json({ erro: "Erro PIX" });
  }
});

// ================= WEBHOOK =================
app.post("/webhook", async (req, res) => {
  try {
    const { external_id, status, amount } = req.body;

    if (status !== "paid") return res.sendStatus(200);

    const pedido = await pool.query("SELECT * FROM pedidos WHERE id=$1", [external_id]);

    if (!pedido.rows[0]) return res.sendStatus(200);
    if (pedido.rows[0].status === "paid") return res.sendStatus(200);

    const valorTotal = Number(amount);
    const valorUser = valorTotal * 0.7;
    const valorSistema = valorTotal * 0.3;

    await pool.query("BEGIN");

    await pool.query("UPDATE pedidos SET status='paid' WHERE id=$1", [external_id]);

    await pool.query(
      "UPDATE users SET saldo = saldo + $1 WHERE id=$2",
      [valorUser, pedido.rows[0].userid]
    );

    await pool.query(
      "INSERT INTO ganhos (valor, userid, pedidoid) VALUES ($1,$2,$3)",
      [valorSistema, pedido.rows[0].userid, external_id]
    );

    await pool.query(
      "INSERT INTO extrato (userid, tipo, valor, descricao) VALUES ($1,$2,$3,$4)",
      [pedido.rows[0].userid, "entrada", valorUser, "PIX recebido"]
    );

    await pool.query("COMMIT");

    res.sendStatus(200);

  } catch (err) {
    await pool.query("ROLLBACK");
    console.error(err);
    res.sendStatus(500);
  }
});

app.listen(PORT, () => {
  console.log("🚀 Sistema rodando profissional");
});
