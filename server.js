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

app.use(cors({
  origin: "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

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
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ erro: "Token ausente" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    return res.status(401).json({ erro: "Token inválido" });
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
      "INSERT INTO users (nome,email,senha,cpf,codigo,saldo) VALUES ($1,$2,$3,$4,$5,0)",
      [nome, email, hash, cpf, codigo]
    );

    await transporter.sendMail({
      to: email,
      subject: "🔐 Código Stark Elite Pay",
      html: emailTemplate(codigo)
    });

    res.json({ message: "Código enviado" });

  } catch {
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

// ================= SALDO =================
app.get("/api/user/balance", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT saldo FROM users WHERE id=$1",
      [req.userId]
    );

    res.json({
      balance: Number(result.rows[0]?.saldo || 0)
    });

  } catch {
    res.json({ balance: 0 });
  }
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
          "x-client-secret": process.env.ELITEPAY_CLIENT_SECRET
        }
      }
    );

    const raw = response.data;

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
          if (typeof value === "object") search(value);
        }
      }

      search(obj);
      return { qr, copia };
    }

    const { qr, copia } = findPixData(raw);

    if (!qr || !copia) {
      return res.status(500).json({ erro: "Erro ao gerar PIX" });
    }

    res.json({ valor, qrCode: qr, pixCopiaECola: copia });

  } catch {
    res.status(500).json({ erro: "Falha ao gerar PIX" });
  }
});

// ================= SAQUE =================
app.post("/withdraw", auth, async (req, res) => {
  try {
    const { valor, chave } = req.body;

    if (!valor || valor <= 0) {
      return res.status(400).json({ erro: "Valor inválido" });
    }

    const user = await pool.query(
      "SELECT saldo FROM users WHERE id=$1",
      [req.userId]
    );

    const saldo = Number(user.rows[0]?.saldo || 0);

    if (saldo < valor) {
      return res.status(400).json({ erro: "Saldo insuficiente" });
    }

    await axios.post(
      "https://api.elitepaybr.com/api/v1/withdraw",
      {
        amount: Number(valor),
        key: chave,
        external_id: Date.now().toString()
      },
      {
        headers: {
          "x-client-id": process.env.ELITEPAY_CLIENT_ID,
          "x-client-secret": process.env.ELITEPAY_CLIENT_SECRET
        }
      }
    );

    await pool.query(
      "UPDATE users SET saldo = saldo - $1 WHERE id=$2",
      [valor, req.userId]
    );

    await pool.query(
      "INSERT INTO extrato (userid, tipo, valor, descricao) VALUES ($1,$2,$3,$4)",
      [req.userId, "saida", valor, "Saque PIX"]
    );

    res.json({ sucesso: true });

  } catch {
    res.status(500).json({ erro: "Erro ao sacar" });
  }
});

// ================= WEBHOOK =================
app.post("/webhook", async (req, res) => {
  const client = await pool.connect();

  try {
    console.log("📩 HEADERS:", req.headers);
    console.log("📩 BODY:", JSON.stringify(req.body, null, 2));

    const body = req.body?.data || req.body;

    if (!body) {
      console.log("❌ Body vazio");
      return res.sendStatus(400);
    }

    const external_id = body.external_id || body.id;
    const status = String(body.status || "").toLowerCase();
    const amount = Number(body.amount || body.value || 0);

    console.log("🔎 Dados extraídos:", {
      external_id,
      status,
      amount
    });

    // ✅ aceitar múltiplos status válidos
    const statusPago = ["paid", "approved", "completed"];

    if (!statusPago.includes(status)) {
      console.log("⏳ Status ignorado:", status);
      return res.sendStatus(200);
    }

    const pedido = await client.query(
      "SELECT * FROM pedidos WHERE id=$1",
      [external_id]
    );

    if (!pedido.rows[0]) {
      console.log("❌ Pedido não encontrado:", external_id);
      return res.sendStatus(200);
    }

    if (pedido.rows[0].status === "paid") {
      console.log("⚠️ Pedido já pago:", external_id);
      return res.sendStatus(200);
    }

    const valorTotal = Number(amount);

    if (valorTotal <= 0) {
      console.log("❌ Valor inválido");
      return res.sendStatus(400);
    }

    if (valorTotal !== Number(pedido.rows[0].valor)) {
      console.log("❌ Valor divergente:", valorTotal, pedido.rows[0].valor);
      return res.sendStatus(400);
    }

    const valorUser = Math.floor(valorTotal * 0.7 * 100) / 100;
    const valorSistema = Math.floor(valorTotal * 0.3 * 100) / 100;

    await client.query("BEGIN");

    const update = await client.query(
      "UPDATE pedidos SET status='paid' WHERE id=$1 AND status='pending'",
      [external_id]
    );

    if (update.rowCount === 0) {
      await client.query("ROLLBACK");
      console.log("⚠️ Nada atualizado");
      return res.sendStatus(200);
    }

    await client.query(
      "UPDATE users SET saldo = saldo + $1 WHERE id=$2",
      [valorUser, pedido.rows[0].userid]
    );

    await client.query(
      "INSERT INTO ganhos (valor, userid, pedidoid) VALUES ($1,$2,$3)",
      [valorSistema, pedido.rows[0].userid, external_id]
    );

    await client.query(
      "INSERT INTO extrato (userid, tipo, valor, descricao) VALUES ($1,$2,$3,$4)",
      [pedido.rows[0].userid, "entrada", valorUser, "PIX confirmado"]
    );

    await client.query("COMMIT");

    console.log("✅ Pagamento confirmado e saldo atualizado!");

    res.sendStatus(200);

  } catch (err) {
    console.error("🔥 ERRO WEBHOOK:", err);

    try {
      await client.query("ROLLBACK");
    } catch {}

    res.sendStatus(500);

  } finally {
    client.release();
  }
});
});
