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
    console.error(err);
    res.status(500).json({ erro: "Erro no cadastro" });
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

// ================= VERIFY =================
app.post("/verify-login", async (req, res) => {
  const { email, codigo } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows[0] || user.rows[0].codigo !== codigo)
    return res.status(400).json({ erro: "Código inválido" });

  const token = jwt.sign({ id: user.rows[0].id }, JWT_SECRET, { expiresIn: "1h" });

  res.json({ token });
});

// ================= PIX =================
app.post("/pix", auth, async (req, res) => {
  try {
    const { valor } = req.body;

    if (!valor || valor <= 0) {
      return res.status(400).json({ erro: "Valor inválido" });
    }

    const id = Date.now().toString();

    await pool.query(
      "INSERT INTO pedidos (id, userid, valor, status) VALUES ($1,$2,$3,$4)",
      [id, req.userId, valor, "pending"]
    );

    const response = await axios.post(
      "https://api.elitepaybr.com/api/v1/deposit",
      {
        amount: Number(valor),
        external_id: id,
        description: "Stark Elite Pay"
      },
      {
        headers: {
          "x-client-id": process.env.ELITEPAY_CLIENT_ID,
          "x-client-secret": process.env.ELITEPAY_CLIENT_SECRET,
          "Content-Type": "application/json"
        }
      }
    );

    const raw = response.data;

    console.log("🔥 RESPOSTA COMPLETA ELITEPAY:");
    console.dir(raw, { depth: null });

    // 🔥 função que procura QR em qualquer lugar
    function findPixData(obj) {
      let qr = null;
      let copia = null;

      function search(o) {
        if (!o || typeof o !== "object") return;

        for (const key in o) {
          const value = o[key];

          if (typeof value === "string") {
            if (!qr && value.startsWith("data:image")) qr = value;
            if (!copia && value.startsWith("000201")) copia = value;
          }

          if (typeof value === "object") {
            search(value);
          }
        }
      }

      search(obj);
      return { qr, copia };
    }

    const { qr, copia } = findPixData(raw);

    if (!qr || !copia) {
      console.log("❌ NÃO FOI POSSÍVEL ENCONTRAR PIX:", raw);

      return res.status(500).json({
        erro: "Formato desconhecido da API",
        retorno: raw
      });
    }

    res.json({
      valor,
      qrCode: qr,
      pixCopiaECola: copia
    });

  } catch (err) {
    console.log("❌ ERRO COMPLETO:");
    console.log("STATUS:", err.response?.status);
    console.log("DATA:", err.response?.data);
    console.log("MSG:", err.message);

    res.status(500).json({
      erro: "Falha ao gerar PIX",
      detalhe: err.response?.data || err.message
    });
  }
});

// ================= WEBHOOK =================
app.post("/webhook", async (req, res) => {
  try {
    const { external_id, status, amount } = req.body;

    if (status !== "paid") return res.sendStatus(200);

    const pedido = await pool.query("SELECT * FROM pedidos WHERE id=$1", [external_id]);

    if (!pedido.rows[0] || pedido.rows[0].status === "paid")
      return res.sendStatus(200);

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
  console.log("🚀 Backend Stark Elite rodando");
});
