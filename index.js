import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { OAuth2Client } from 'google-auth-library';

dotenv.config();
const app = express();
app.use(express.json());
// ---------------------
// CORS
// ---------------------
const corsOptions = {
  origin: process.env.CLIENT_URL, // tu frontend en Vercel
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"],
  credentials: true
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Responder preflight OPTIONS


// DB Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectionLimit: 10
});

app.get('/', (req, res) => {
  res.send('Servidor Railway funcionando 🚀');
});

// Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ---------------------
// Auth - Registro
// ---------------------
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'Todos los campos son requeridos' });

    const [existing] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    if (existing.length) return res.status(400).json({ error: 'Usuario ya registrado' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, hashedPassword, role || 'user']
    );

    res.json({ id: result.insertId, username, role: role || 'user' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, username, email, role FROM users');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error obteniendo usuarios' });
  }
});

// ---------------------
// Auth - Login
// ---------------------
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email y contraseña son requeridos" });

    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [email]);
    if (!rows.length) return res.status(401).json({ error: "Usuario no encontrado" });

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(401).json({ error: "Contraseña incorrecta" });

    const secret = process.env.JWT_SECRET || "clave_default";
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      secret,
      { expiresIn: "1h" }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    console.error("❌ Error en /api/login:", err.message);
    res.status(500).json({ error: "Error en login" });
  }
});

// ---------------------
// Google Login
// ---------------------
app.post('/api/google-login', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token de Google requerido' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const username = payload.name || payload.email.split('@')[0];

    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    let user;

    if (!rows.length) {
      const [result] = await pool.query(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
        [username, email, null, 'user']
      );
      user = { id: result.insertId, username, email, role: 'user' };
    } else {
      user = rows[0];
    }

    const jwtToken = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token: jwtToken, role: user.role });
  } catch (err) {
    console.error('Error login Google:', err);
    res.status(400).json({ error: 'Token de Google inválido' });
  }
});

// ---------------------
// Productos
// ---------------------
app.get('/api/products', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT p.*, COALESCE(c.nombre_categoria, 'Sin categoría') AS categoria
      FROM products p
      LEFT JOIN categorias c ON p.id_categoria = c.id_categoria
      WHERE p.status='Activo'
      ORDER BY p.id DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error obteniendo productos' });
  }
});

// ---------------------
// Categorías
// ---------------------
app.get('/api/categorias', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id_categoria, nombre_categoria FROM categorias');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al obtener categorías' });
  }
});

app.post('/api/categorias', async (req, res) => {
  try {
    const { nombre_categoria } = req.body;
    if (!nombre_categoria || !nombre_categoria.trim()) {
      return res.status(400).json({ error: 'El nombre de la categoría es requerido' });
    }

    const [result] = await pool.query('INSERT INTO categorias (nombre_categoria) VALUES (?)', [nombre_categoria]);
    res.json({ id: result.insertId, nombre_categoria });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error creando categoría' });
  }
});

// ---------------------
// CRUD Productos
// ---------------------
app.post('/api/products', async (req, res) => {
  try {
    const { name, description, price, stock, image_url, id_categoria } = req.body;

    // Validaciones
    if (!id_categoria || !name || !description || price == null || stock == null) {
      return res.status(400).json({ error: 'Debe llenar todos los campos' });
    }

    const priceNum = Number(price);
    const stockNum = Number(stock);

    if (isNaN(priceNum) || priceNum < 0 || isNaN(stockNum) || stockNum < 0) {
      return res.status(400).json({ error: 'Precio o stock inválido' });
    }

    // Insertar producto
    const [result] = await pool.query(
      `INSERT INTO products 
      (name, description, price, stock, image_url, status, discount, discount_expiration, id_categoria) 
      VALUES (?,?,?,?,?,?,?,?,?)`,
      [name, description, priceNum, stockNum, image_url || '', 'Activo', 0, null, id_categoria]
    );

    // Opcional: traer el nombre de la categoría para el frontend
    const [categoriaRows] = await pool.query(
      'SELECT nombre_categoria FROM categorias WHERE id_categoria = ?',
      [id_categoria]
    );

    res.json({
      id: result.insertId,
      name,
      description,
      price: priceNum,
      stock: stockNum,
      image_url: image_url || '',
      status: 'Activo',
      discount: 0,
      discount_expiration: null,
      id_categoria,
      categoria: categoriaRows[0]?.nombre_categoria || 'Sin categoría'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error creando producto' });
  }
});

app.put('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, image_url, discount, discount_expiration, id_categoria } = req.body;
    if (!name || !description || !price || !image_url || discount == null || !id_categoria)
      return res.status(400).json({ error: 'Todos los campos son requeridos' });

    const [result] = await pool.query(
      `UPDATE products 
       SET name=?, description=?, price=?, image_url=?, discount=?, discount_expiration=?, id_categoria=? 
       WHERE id=?`,
      [name, description, price, image_url, discount, discount_expiration, id_categoria, id]
    );

    if (result.affectedRows === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json({ message: 'Producto actualizado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error actualizando producto' });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const [result] = await pool.query('DELETE FROM products WHERE id = ?', [id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json({ message: 'Producto eliminado' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error eliminando producto' });
  }
});

// ---------------------
// Órdenes
// ---------------------
app.get('/api/orders', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, name, email, address_line, city, country, total, payment_intent_id, status, order_date, created_at
      FROM orders
      ORDER BY created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    console.error('❌ Error obteniendo órdenes:', err);
    res.status(500).json({ error: 'Error obteniendo órdenes' });
  }
});

// ---------------------
// Mis Órdenes por usuario
// ---------------------
app.get('/api/my_orders/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const [rows] = await pool.query(`
      SELECT id, name, email, address_line, city, country, total, payment_intent_id, status, order_date, created_at
      FROM orders
      WHERE email = ?
      ORDER BY created_at DESC
    `, [email]);
    res.json(rows);
  } catch (err) {
    console.error('❌ Error obteniendo mis órdenes:', err);
    res.status(500).json({ error: 'Error obteniendo mis órdenes' });
  }
});

// ---------------------
// Actualizar estado de Orden
// ---------------------
app.put("/api/orders/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ error: "El campo status es requerido" });
    }

    const [result] = await pool.query(
      "UPDATE orders SET status=? WHERE id=?",
      [status, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Orden no encontrada" });
    }

    res.json({ message: `Estado de la orden ${id} actualizado a ${status}` });
  } catch (err) {
    console.error("❌ Error actualizando orden:", err);
    res.status(500).json({ error: "Error actualizando orden" });
  }
});

// ---------------------
// Items de Órdenes
// ---------------------
app.get("/api/order_items", async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        oi.id AS id,
        oi.order_id,
        o.name AS customer_name,
        o.email AS customer_email,
        o.phone AS customer_phone,
        o.address_line AS customer_address,
        o.city AS customer_city,
        o.payment_intent_id AS orden_payment_intent,
        p.id AS product_id,
        p.name AS product_name,
        oi.quantity,
        oi.unit_price,
        oi.line_total,
        oi.created_date,
        o.order_date,
        o.created_at AS order_created_at
      FROM order_items oi
      LEFT JOIN orders o ON oi.order_id = o.id
      LEFT JOIN products p ON oi.product_id = p.id
      ORDER BY oi.order_id DESC, oi.id DESC;
    `);
    console.log(`✅ Se encontraron ${rows.length} registros`);
    res.json(rows);
  } catch (error) {
    console.error("❌ Error obteniendo order_items:", error);
    res.status(500).json({ error: "Error al obtener los items de las órdenes" });
  }
});

// ---------------------
// Middleware: verificar token JWT
// ---------------------
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token requerido" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET || "clave_default", (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido o expirado" });
    req.user = user;
    next();
  });
};

// ---------------------
// Valoración de Productos
// ---------------------
app.post("/api/products/:id/rating", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { rating, comment } = req.body;
  const userId = req.user.id;

  if (!rating || rating < 1 || rating > 5) {
    return res.status(400).json({ error: "Valor inválido" });
  }

  try {
    await pool.query(
      `INSERT INTO ratings (product_id, user_id, rating, comment)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE rating = VALUES(rating), comment = VALUES(comment)`,
      [id, userId, rating, comment]
    );

    const [rows] = await pool.query(
      "SELECT AVG(rating) AS avg FROM ratings WHERE product_id = ?",
      [id]
    );
    const avg = rows[0].avg;

    await pool.query("UPDATE products SET rating = ? WHERE id = ?", [avg, id]);

    res.json({ message: "Valoración registrada ✅", average: avg });
  } catch (err) {
    console.error("❌ Error registrando valoración:", err);
    res.status(500).json({ error: "Error al registrar valoración" });
  }
});

app.get("/api/products/:id/ratings", async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(
      `SELECT r.id, r.rating, r.comment, r.created_at, u.username AS user
       FROM ratings r
       JOIN users u ON r.user_id = u.id
       WHERE r.product_id = ?
       ORDER BY r.created_at DESC`,
      [id]
    );
    res.json(rows);
  } catch (err) {
    console.error("❌ Error obteniendo valoraciones:", err);
    res.status(500).json({ error: "Error al obtener valoraciones" });
  }
});

// ---------------------
// PayPal - Crear Orden
// ---------------------
app.post('/api/create-paypal-order', async (req, res) => {
  const { items } = req.body;

  try {
    const total = items.reduce((sum, i) => sum + i.qty * i.price, 0);
    if (total <= 0) return res.status(400).json({ error: 'Total inválido' });

    const totalFixed = total.toFixed(2);

    // Crear la orden en PayPal
    const response = await axios.post(
      'https://api-m.sandbox.paypal.com/v2/checkout/orders',
      {
        intent: 'CAPTURE',
        purchase_units: [{ amount: { currency_code: 'USD', value: totalFixed } }]
      },
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Basic ${Buffer.from(
            `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`
          ).toString('base64')}`
        }
      }
    );

    const orderID = response.data.id;

    // Devuelve solo el orderID al frontend
    res.json({ orderID });

  } catch (err) {
    console.error('❌ Error creando orden PayPal:', err.response?.data || err.message);
    res.status(500).json({ error: 'Error creando orden PayPal', details: err.response?.data || err.message });
  }
});

// ---------------------
// Capturar pago PayPal
// ---------------------
app.post('/api/capture-paypal-order', async (req, res) => {
  const connection = await pool.getConnection();
  const { orderID, items, customer_name, email, phone, address_line, city, country } = req.body;

  if (!orderID) return res.status(400).json({ error: 'No se proporcionó orderID' });

  try {
    const response = await axios.post(
      `https://api-m.sandbox.paypal.com/v2/checkout/orders/${orderID}/capture`,
      {},
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Basic ${Buffer.from(
            `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_SECRET}`
          ).toString('base64')}`
        }
      }
    );

    const details = response.data;
    if (details.status !== 'COMPLETED') {
      return res.status(400).json({ error: 'Pago no completado' });
    }

    await connection.beginTransaction();

    // Lógica de fechas y reprogramación
    const MAX_ORDERS_PER_DAY = 4;
    let orderDate = new Date();
    orderDate.setHours(0, 0, 0, 0);
    let formattedDate = orderDate.toISOString().split("T")[0];
    let reprogrammed = 0;

    const [ordersToday] = await connection.query(
      "SELECT COUNT(*) AS total FROM orders WHERE order_date = ?",
      [formattedDate]
    );

    if (ordersToday[0].total >= MAX_ORDERS_PER_DAY) {
      let nextDate = new Date(orderDate);
      let found = false;
      while (!found) {
        nextDate.setDate(nextDate.getDate() + 1);
        const nextFormatted = nextDate.toISOString().split("T")[0];
        const [ordersNext] = await connection.query(
          "SELECT COUNT(*) AS total FROM orders WHERE order_date = ?",
          [nextFormatted]
        );
        if (ordersNext[0].total < MAX_ORDERS_PER_DAY) {
          formattedDate = nextFormatted;
          reprogrammed = 1;
          found = true;
        }
      }
    }

    const total = items.reduce((sum, i) => sum + i.qty * i.price, 0);

    // Guardar orden
    const [orderResult] = await connection.query(
      `INSERT INTO orders 
       (name, email, phone, address_line, city, country, total, status, payment_intent_id, order_date, reprogrammed, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, "paid", ?, ?, ?, NOW())`,
      [
        customer_name || 'Cliente',
        email || 'no-email@mail.com',
        phone || 'Sin teléfono',
        address_line || 'Sin dirección',
        city || 'Sin ciudad',
        country || 'Sin país',
        total,
        orderID,
        formattedDate,
        reprogrammed
      ]
    );

    const newOrderId = orderResult.insertId;

    // Insertar items y actualizar stock
    if (items && items.length > 0) {
      const itemsValues = items.map(i => [newOrderId, i.productId, i.qty, i.price, i.qty * i.price]);
      await connection.query(
        `INSERT INTO order_items (order_id, product_id, quantity, unit_price, line_total) VALUES ?`,
        [itemsValues]
      );

      for (const item of items) {
        const [updateResult] = await connection.query(
          `UPDATE products 
           SET stock = stock - ? 
           WHERE id = ? AND stock >= ?`,
          [item.qty, item.productId, item.qty]
        );

        if (updateResult.affectedRows === 0) {
          throw new Error(`No hay suficiente stock para el producto ID ${item.productId}`);
        }
      }
    }

    await connection.commit();

    const message = reprogrammed
      ? `✅ Orden pagada y reprogramada para el día ${formattedDate}.`
      : `✅ Orden pagada para el día ${formattedDate}.`;

    res.json({ status: 'success', message, orderID: newOrderId });

  } catch (err) {
    await connection.rollback();
    console.error('❌ Error capturando orden PayPal:', err.response?.data || err.message);
    res.status(500).json({ error: 'Error capturando orden PayPal', details: err.response?.data || err.message });
  } finally {
    connection.release();
  }
});

// ---------------------
// Ventas
// ---------------------
app.post("/api/ventas", async (req, res) => {
  const connection = await pool.getConnection();
  try {
    const { orderID, items, status, userId } = req.body;
    if (!orderID || !items?.length) 
      return res.status(400).json({ error: "Faltan datos de la venta" });

    const itemsWithPrice = items.map(i => ({
      ...i,
      price: i.price ? i.price : 0
    }));

    const total = itemsWithPrice.reduce(
      (sum, item) => sum + Number(item.price) * Number(item.qty),
      0
    );

    await connection.beginTransaction();

    // Insertar la venta
    const [result] = await connection.query(
      `INSERT INTO ventas (orderID, userId, items, total, status, fecha) 
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [orderID, userId || null, JSON.stringify(itemsWithPrice), total.toFixed(2), status || "pending"]
    );

    // 🔹 Actualizar stock de cada producto
    for (const item of itemsWithPrice) {
      const [updateResult] = await connection.query(
        `UPDATE products 
         SET stock = stock - ? 
         WHERE id = ? AND stock >= ?`,
        [item.qty, item.productId, item.qty]
      );

      if (updateResult.affectedRows === 0) {
        throw new Error(`No hay suficiente stock para el producto ID ${item.productId}`);
      }
    }

    await connection.commit();

    res.json({ message: "Venta registrada ✅ y stock actualizado", id: result.insertId, total: total.toFixed(2) });

  } catch (err) {
    await connection.rollback();
    console.error("❌ Error registrando venta:", err.message);
    res.status(500).json({ error: "Error al registrar la venta", details: err.message });
  } finally {
    connection.release();
  }
});

app.get("/api/ventas", async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT id, orderID, items, total, status, fecha FROM ventas ORDER BY fecha DESC`);
    res.json(rows);
  } catch (err) {
    console.error("❌ Error obteniendo ventas:", err);
    res.status(500).json({ error: "Error obteniendo ventas" });
  }
});

//----------------------
//Zona de Estadisticas
//----------------------
app.get("/api/dashboard-stats", async (req, res) => {
  try {
    const [orders] = await pool.query("SELECT total, status, DATE(created_at) AS date FROM orders");
    const [orderItems] = await pool.query("SELECT order_items.product_id, products.name AS product_name, order_items.quantity FROM order_items JOIN products ON order_items.product_id = products.id");

    const totalSales = orders.reduce((sum, o) => sum + o.total, 0);
    const totalOrders = orders.length;
    const completedOrders = orders.filter(o => o.status === 'paid').length;
    const pendingOrders = orders.filter(o => o.status === 'pending').length;

    const salesByDate = [];
    const mapByDate = {};
    orders.forEach(o => {
      if (!mapByDate[o.date]) mapByDate[o.date] = 0;
      mapByDate[o.date] += o.total;
    });
    for (let date in mapByDate) salesByDate.push({ date, total: mapByDate[date] });

    const topProductsMap = {};
    orderItems.forEach(i => {
      if (!topProductsMap[i.product_id]) topProductsMap[i.product_id] = { name: i.product_name, quantity: 0 };
      topProductsMap[i.product_id].quantity += i.quantity;
    });
    const topProducts = Object.values(topProductsMap).sort((a, b) => b.quantity - a.quantity).slice(0, 5);

    res.json({ totalSales, totalOrders, completedOrders, pendingOrders, salesByDate, topProducts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error obteniendo estadísticas" });
  }
});

// ---------------------
// Servidor
// ---------------------
app.listen(process.env.PORT || 4000, () => {
  console.log(`🚀 Servidor corriendo en el puerto ${process.env.PORT || 4000}`);
});
