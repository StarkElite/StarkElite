require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(cors({ origin: "*" }));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
}));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// ================= DB =================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ================= EMAIL =================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function gerarCodigo() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function emailTemplate(codigo, tipo = "login") {
  return `
  <div style="background:#0b0f1a;padding:40px 0;font-family:Arial;color:#e5e7eb;">
    <div style="max-width:520px;margin:auto;background:#111827;border-radius:16px;padding:32px;">
      <h1 style="text-align:center;color:#00d4ff;">Stark Elite Pay</h1>
      <h2 style="text-align:center;color:#fff;">
        ${tipo === "login" ? "Verificação de Login" : "Confirmação de Cadastro"}
      </h2>
      <div style="text-align:center;margin:30px 0;">
        <span style="font-size:36px;color:#00d4ff;letter-spacing:8px;">
          ${codigo}
        </span>
      </div>
      <p style="text-align:center;color:#9ca3af;">
        Código válido por 10 minutos
      </p>
    </div>
  </div>`;
}

function emailSaqueTemplate(valor, data) {
  return `
  <div style="background:#0b0f1a;padding:40px 0;font-family:Arial;color:#e5e7eb;">
    <div style="max-width:520px;margin:auto;background:#111827;border-radius:16px;padding:32px;">
      <h1 style="text-align:center;color:#00d4ff;">Stark Elite Pay</h1>
      <h2 style="text-align:center;color:#fff;">💸 Saque confirmado</h2>
      <div style="text-align:center;margin:30px 0;">
        <span style="font-size:32px;color:#22c55e;">
          R$ ${Number(valor).toFixed(2)}
        </span>
      </div>
      <p style="text-align:center;color:#9ca3af;">
        ${data}
      </p>
      <p style="text-align:center;color:#facc15;">
        Se não foi você, altere sua senha imediatamente.
      </p>
    </div>
  </div>`;
}

// ================= AUTH =================
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ erro: "Token ausente" });

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
    const { nome, email, senha } = req.body;

    const exist = await pool.query("SELECT id FROM users WHERE email=$1", [email]);
    if (exist.rows.length)
      return res.status(400).json({ erro: "Email já existe" });

    const hash = await bcrypt.hash(senha, 12);
    const codigo = gerarCodigo();

    await pool.query(
      "INSERT INTO users (nome,email,senha,saldo,codigo,verificado) VALUES ($1,$2,$3,0,$4,false)",
      [nome, email, hash, codigo]
    );

    await transporter.sendMail({
      to: email,
      subject: "🔐 Confirmação de Cadastro",
      html: emailTemplate(codigo, "register")
    });

    res.json({ message: "Código enviado" });

  } catch (err) {
    console.error(err);
    res.status(500).json({ erro: "Erro cadastro" });
  }
});

// ================= VERIFY REGISTER =================
app.post("/verify-register", async (req, res) => {
  const { email, codigo } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows[0] || user.rows[0].codigo !== codigo)
    return res.status(400).json({ erro: "Código inválido" });

  await pool.query("UPDATE users SET verificado=true WHERE email=$1", [email]);

  res.json({ ok: true });
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows[0] || !user.rows[0].verificado)
    return res.status(400).json({ erro: "Conta inválida" });

  const ok = await bcrypt.compare(senha, user.rows[0].senha);
  if (!ok) return res.status(400).json({ erro: "Senha inválida" });

  const codigo = gerarCodigo();

  await pool.query("UPDATE users SET codigo=$1 WHERE email=$2", [codigo, email]);

  await transporter.sendMail({
    to: email,
    subject: "🔑 Código de Login",
    html: emailTemplate(codigo, "login")
  });

  res.json({ message: "Código enviado" });
});

// ================= VERIFY LOGIN =================
app.post("/verify-login", async (req, res) => {
  const { email, codigo } = req.body;

  const user = await pool.query("SELECT * FROM users WHERE email=$1", [email]);

  if (!user.rows[0] || user.rows[0].codigo !== codigo)
    return res.status(400).json({ erro: "Código inválido" });

  const token = jwt.sign({ id: user.rows[0].id }, JWT_SECRET, { expiresIn: "1d" });

  res.json({ token });
});

// ================= BALANCE =================
app.get("/balance", auth, async (req, res) => {
  const r = await pool.query("SELECT saldo FROM users WHERE id=$1", [req.userId]);
  res.json({ balance: Number(r.rows[0]?.saldo || 0) });
});

// ================= DEPOSIT =================
app.post("/deposit", auth, async (req, res) => {
  try {
    const valor = Number(req.body.valor);

    if (!valor || valor < 5 || valor > 2000) {
      return res.status(400).json({
        erro: "Valor do PIX deve ser entre R$ 5,00 e R$ 2.000,00"
      });
    }

    const id = crypto.randomUUID();

    await pool.query(
      "INSERT INTO pedidos (id, userid, valor, status) VALUES ($1,$2,$3,'pending')",
      [id, req.userId, valor]
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

    const data = response.data;

    console.log("🔥 RESPOSTA ELITEPAY:", data);

    // 🔥 PEGA QUALQUER POSSÍVEL CAMPO DE PIX
    const copiaECola =
      data.pixCopiaECola ||
      data.pix_code ||
      data.payload ||
      data.emv ||
      data.copyPaste ||
      data.brcode ||
      data.code ||
      data.qr ||
      data.qrCode ||
      null;

    // 🔥 LIMPEZA (remove espaços/quebras)
    const cleanPix = copiaECola ? copiaECola.toString().trim() : null;

    // 🔥 VALIDA SE É UM PIX REAL (começa com 000201)
    if (!cleanPix || !cleanPix.startsWith("000201")) {
      console.error("❌ PIX INVÁLIDO RECEBIDO:", data);
      return res.status(500).json({
        erro: "PIX inválido retornado pela API",
        raw: data
      });
    }

    return res.json({
      copiaECola: cleanPix,
      qrCode: cleanPix // frontend gera o QR
    });

  } catch (err) {
    console.error("❌ ERRO DEPOSIT:", err?.response?.data || err.message);
    return res.status(500).json({
      erro: "Erro ao gerar PIX"
    });
  }
});
// ================= WITHDRAW =================
app.post("/withdraw", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const valor = Number(req.body.valor);
    const { chave } = req.body;

    // ✅ LIMITE ADICIONADO
    if (!valor || valor < 50 || valor > 1000) {
      return res.status(400).json({
        erro: "Saque deve ser entre R$ 50,00 e R$ 1.000,00"
      });
    }

    const user = await client.query(
      "SELECT saldo,email FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (user.rows[0].saldo < valor)
      return res.status(400).json({ erro: "Saldo insuficiente" });

    const id = crypto.randomUUID();

    await client.query("BEGIN");

    await client.query(
      "INSERT INTO saques (id, userid, valor, status) VALUES ($1,$2,$3,'pending')",
      [id, req.userId, valor]
    );

    await client.query("COMMIT");

    await axios.post(
      "https://api.elitepaybr.com/api/v1/withdraw",
      { amount: valor, key: chave, external_id: id },
      {
        headers: {
          "x-client-id": process.env.ELITEPAY_CLIENT_ID,
          "x-client-secret": process.env.ELITEPAY_CLIENT_SECRET
        }
      }
    );

    res.json({ ok: true, status: "pending" });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ erro: "Erro saque" });
  } finally {
    client.release();
  }
});

// ================= WEBHOOK =================
app.post("/webhook", async (req, res) => {
  const client = await pool.connect();

  try {
    const body = req.body?.data || req.body;

    const id = body.external_id || body.transactionId;
    const status = String(body.transactionState || body.status || "").toLowerCase();
    const amount = Number(body.value || body.amount || 0);

    const aprovado = ["completo", "deposito_completo", "saque_completo"];

    if (!aprovado.includes(status))
      return res.sendStatus(200);

    await client.query("BEGIN");

    const pedido = await client.query(
      "SELECT * FROM pedidos WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (pedido.rows[0] && pedido.rows[0].status !== "paid") {
      await client.query("UPDATE pedidos SET status='paid' WHERE id=$1", [id]);
      await client.query(
        "UPDATE users SET saldo = saldo + $1 WHERE id=$2",
        [amount, pedido.rows[0].userid]
      );
    }

    const saque = await client.query(
      "SELECT * FROM saques WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (saque.rows[0] && saque.rows[0].status !== "done") {
      await client.query("UPDATE saques SET status='done' WHERE id=$1", [id]);

      await client.query(
        "UPDATE users SET saldo = saldo - $1 WHERE id=$2",
        [amount, saque.rows[0].userid]
      );

      const user = await client.query(
        "SELECT email FROM users WHERE id=$1",
        [saque.rows[0].userid]
      );

      const data = new Date().toLocaleString("pt-BR");

      await transporter.sendMail({
        to: user.rows[0].email,
        subject: "💸 Saque confirmado",
        html: emailSaqueTemplate(amount, data)
      });
    }

    await client.query("COMMIT");

    res.sendStatus(200);

  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.sendStatus(500);
  } finally {
    client.release();
  }
});

// ================= START =================
app.listen(PORT, () => {
  console.log("🚀 Banco rodando na porta", PORT);
});
