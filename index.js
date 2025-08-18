import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import Stripe from 'stripe';

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CLIENT_URL }));

// DB Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectionLimit: 10
});

// Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

// Utils
const getProductsByIds = async (ids) => {
  if (!ids.length) return [];
  const placeholders = ids.map(() => '?').join(',');
  const [rows] = await pool.query(`SELECT * FROM products WHERE id IN (${placeholders}) AND active=1`, ids);
  return rows;
};

// Rutas: Productos
app.get('/api/products', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM products WHERE active=1 ORDER BY id DESC');
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

app.get('/api/products/:id', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM products WHERE id=? AND active=1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'No encontrado' });
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'Error' });
  }
});

/**
 * Crear PaymentIntent
 * Body: { items: [{productId, qty}], customer: {name,email,address_line,city,country} }
 * Recalcula el monto en backend para seguridad.
 */
app.post('/api/create-payment-intent', async (req, res) => {
  try {
    const { items } = req.body;
    const ids = (items || []).map(i => i.productId);
    const products = await getProductsByIds(ids);

    // Mapear y calcular total
    const priceMap = new Map(products.map(p => [p.id, p.price_cents]));
    const stockMap = new Map(products.map(p => [p.id, p.stock]));
    let amount = 0;

    for (const i of items) {
      const price = priceMap.get(i.productId);
      const stock = stockMap.get(i.productId);
      if (price == null) return res.status(400).json({ error: 'Producto inválido' });
      if (i.qty < 1 || i.qty > stock) return res.status(400).json({ error: 'Cantidad no disponible' });
      amount += price * i.qty;
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: process.env.CURRENCY || 'usd',
      automatic_payment_methods: { enabled: true },
      metadata: { integration_check: 'accept_a_payment' }
    });

    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'No se pudo crear el pago' });
  }
});

/**
 * Confirmar Pedido tras pago exitoso
 * Body: { paymentIntentId, customer: {...}, items: [{productId, qty}] }
 */
app.post('/api/orders/confirm', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { paymentIntentId, customer, items } = req.body;
    const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
    if (pi.status !== 'succeeded') return res.status(400).json({ error: 'Pago no confirmado' });

    // Recalcular total
    const ids = (items || []).map(i => i.productId);
    const products = await getProductsByIds(ids);
    const priceMap = new Map(products.map(p => [p.id, p.price_cents]));
    let total = 0;
    for (const i of items) {
      const price = priceMap.get(i.productId);
      if (price == null) return res.status(400).json({ error: 'Producto inválido' });
      total += price * i.qty;
    }

    await conn.beginTransaction();

    // Crear orden
    const [orderRes] = await conn.query(
      `INSERT INTO orders (customer_name,email,address_line,city,country,total_cents,status,payment_intent_id)
       VALUES (?,?,?,?,?,?, 'paid', ?)`,
      [
        customer?.name || null,
        customer?.email || null,
        customer?.address_line || null,
        customer?.city || null,
        customer?.country || null,
        total,
        paymentIntentId
      ]
    );
    const orderId = orderRes.insertId;

    // Items + disminuir stock
    for (const i of items) {
      const unit = priceMap.get(i.productId);
      const line = unit * i.qty;
      await conn.query(
        `INSERT INTO order_items (order_id, product_id, quantity, unit_price_cents, line_total_cents)
         VALUES (?,?,?,?,?)`,
        [orderId, i.productId, i.qty, unit, line]
      );
      await conn.query(`UPDATE products SET stock = stock - ? WHERE id=? AND stock >= ?`, [i.qty, i.productId, i.qty]);
    }

    await conn.commit();
    res.json({ ok: true, orderId });
  } catch (e) {
    await conn.rollback();
    console.error(e);
    res.status(500).json({ error: 'No se pudo guardar el pedido' });
  } finally {
    conn.release();
  }
});

/**
 * (Opcional) Webhook de Stripe para confirmar pedidos automáticamente
 * Configura el endpoint en Stripe si lo usas.
 */
// import crypto from 'crypto';
// app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => { /* ... */ });

app.listen(process.env.PORT, () => {
  console.log('API corriendo en puerto', process.env.PORT);
});
