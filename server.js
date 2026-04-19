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
  `);

  res.send("Banco atualizado 🚀");
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
      subject: "🔐 Código de cadastro",
      html: `<h1>${codigo}</h1>`
    });

    res.json({ message: "Código enviado" });

  } catch (err) {
    if (err.code === "23505")
      return res.status(400).json({ erro: "Email já cadastrado" });

    res.status(500).json({ erro: "Erro interno" });
  }
});

// ================= VERIFY =================
app.post("/verify", async (req, res) => {
  const { email, codigo } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows[0] || user.rows[0].codigo !== codigo)
    return res.status(400).json({ erro: "Código inválido" });

  await pool.query("UPDATE users SET verificado=true WHERE email=$1", [email]);

  res.json({ message: "Conta verificada" });
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
    html: `<h1>${codigo}</h1>`
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

// ================= GERAR PIX =================
app.post("/gerar-pix", auth, async (req, res) => {
  try {
    const { valor } = req.body;

    if (!Number.isFinite(valor))
      return res.status(400).json({ erro: "Valor inválido" });

    if (valor < 10)
      return res.status(400).json({ erro: "Mínimo R$10" });

    if (valor > 2000)
      return res.status(400).json({ erro: "Máximo R$2000" });

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
          "x-client-secret": process.env.ELITEPAY_CLIENT_SECRET,
          "Content-Type": "application/json"
        }
      }
    );

    res.json(response.data);

  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).json({ erro: "Erro ao gerar Pix" });
  }
});

// ================= WEBHOOK =================
app.post("/webhook", async (req, res) => {
  try {
    const { external_id, status, amount } = req.body;

    if (status !== "paid") return res.sendStatus(200);

    const pedido = await pool.query(
      "SELECT * FROM pedidos WHERE id=$1",
      [external_id]
    );

    if (!pedido.rows[0]) return res.sendStatus(200);
    if (pedido.rows[0].status === "paid") return res.sendStatus(200);

    const userId = pedido.rows[0].userid;
    const valorUser = amount * 0.7;

    await pool.query("BEGIN");

    await pool.query("UPDATE pedidos SET status='paid' WHERE id=$1", [external_id]);

    await pool.query(
      "UPDATE users SET saldo = saldo + $1 WHERE id=$2",
      [valorUser, userId]
    );

    await pool.query("COMMIT");

    res.sendStatus(200);

  } catch (err) {
    await pool.query("ROLLBACK");
    console.error(err);
    res.sendStatus(500);
  }
});

// ================= SAQUE =================
app.post("/confirmar-saque", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const { valor, chavePix, tipo } = req.body;

    if (!Number.isFinite(valor))
      return res.status(400).json({ erro: "Valor inválido" });

    if (valor < 50)
      return res.status(400).json({ erro: "Saque mínimo R$50" });

    if (valor > 1000)
      return res.status(400).json({ erro: "Saque máximo R$1000" });

    await client.query("BEGIN");

    const user = await client.query(
      "SELECT saldo FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (user.rows[0].saldo < valor) {
      await client.query("ROLLBACK");
      return res.status(400).json({ erro: "Saldo insuficiente" });
    }

    await axios.post(
      "https://api.elitepaybr.com/api/v1/withdraw",
      {
        amount: valor,
        pixKey: chavePix,
        pixKeyType: tipo
      },
      {
        headers: {
          "x-client-id": process.env.ELITEPAY_CLIENT_ID,
          "x-client-secret": process.env.ELITEPAY_CLIENT_SECRET,
          "Content-Type": "application/json"
        }
      }
    );

    await client.query(
      "UPDATE users SET saldo = saldo - $1 WHERE id=$2",
      [valor, req.userId]
    );

    await client.query("COMMIT");

    res.json({ message: "Saque enviado com sucesso" });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err.response?.data || err);
    res.status(500).json({ erro: "Erro no saque" });
  } finally {
    client.release();
  }
});

app.listen(PORT, () => {
  console.log("🚀 Rodando...");
});