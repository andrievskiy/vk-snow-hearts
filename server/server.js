import express from 'express';
import compression from 'compression';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VK_PLATFORM = 'vk';
const OK_PLATFORM  = 'ok';

const app = express();
app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // VK sends x-www-form-urlencoded

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// ===== Catalog for get_item =====
const CATALOG = {
  convert_all_1: {
    item_id: 'convert_all_1',
    title: 'Превратить все снежинки',
    price: 1
  },
  item1: {
    item_id: 'item1',
    title: 'Тестовый айтем за 10',
    price: 10
  },
  item2: {
    item_id: 'item2',
    title: 'Тестовый айтем за 2',
    price: 2
  }
};

const SUBSCRIPTIONS_CATALOG = {
  sub1: {
    item_id: "sub1",
    title:"Убрать какашки на неделю",
    photo_url:"",
    price: 2,
    period: 7,
    trial_duration: 3,
    expiration: 0
  }
}

app.use((req, res, next) => {
  const send = res.send;
  res.send = content => {
    const time = new Date();
    console.log(`<<< ${time} [${req.path}](${res.statusCode})`, content);
    res.send = send;
    return res.send(content);
  }

  next();
});

function logRequest(platform, req) {
  const body = req.method === 'GET' ? req.query : req.body;
  const time = new Date();
  console.log(`>>> ${time} Incoming request [${req.method}][${platform}][${req.path}] BODY: `, body);
}

function logError(platform, req, errorText) {
  const body = req.method === 'GET' ? req.query : req.body;
  const time = new Date();

  console.error(`[ERROR] [${time}] ${errorText}`);
  console.error(`[ERROR] ON [${platform}][${req.path}] REQ BODY: `, body);
}

// ---- Tolerant VK Payments signature check (MD5) ----
function vkPaymentsCheckSig(params, appSecret) {
  const entries = Object.keys(params)
    .filter(k => k !== 'sig')
    .sort()
    .map(k => `${k}=${params[k]}`);

  const sig = String(params.sig || '').toLowerCase();

  // A) classic (no separators)
  const plain = entries.join('') + appSecret;
  const md5Plain = crypto.createHash('md5').update(plain).digest('hex');
  if (md5Plain === sig) return true;

  // B) docs variant (&-joined)
  const amp = entries.join('&') + appSecret;
  const md5Amp = crypto.createHash('md5').update(amp).digest('hex');
  if (md5Amp === sig) return true;

  return false;
}

// Compute signature: sig = MD5( concat(sorted key=value, without 'sig') + OK_SECRET_KEY )
function okCheckSig(params, secret) {
  const parts = Object.keys(params)
    .filter(k => k !== 'sig')
    .sort()
    .map(k => `${k}=${params[k]}`)
    .join('');
  const md5 = crypto.createHash('md5').update(parts + secret).digest('hex');
  return md5 === String(params.sig || '').toLowerCase();
}


function getAppSecret(appId) {
  const key = `APP_SECRET_${appId}`;
  return process.env[key];
}

// ===== Payments Callback =====
app.all('/api/payments/callback/:appId', async (req, res) => {
  try {
    logRequest(VK_PLATFORM, req);
    const body = req.method === 'GET' ? req.query : req.body;
    const appId = req.params.appId;
    const appSecret = getAppSecret(appId);
    // if (!appSecret) {
    //   logError(VK_PLATFORM, req, `Can't get app secret for appId: ${appId}`);
    //   return res.status(500).send(`Can't get app secret for appId: ${appId}`);
    // }
    //
    // if (!vkPaymentsCheckSig(body, appSecret)) {
    //   logError(VK_PLATFORM, req, `Sign mismatch`);
    //   return res.status(403).send('sig mismatch');
    // }

    const type = body.notification_type;

    switch (type) {
      case 'get_item':
      case 'get_item_test':
        const itemId = body.item || body.item_id;
        const product = CATALOG[itemId];

        if (!product) {
          console.warn(`[${VK_PLATFORM}] Invalid product ${itemId}`);
          return res.json({ error: { error_code: 20, error_msg: 'Item not found' } });
        }

        return res.json({ response: { item_id: product.item_id, title: product.title, price: product.price } });

      case 'order_status_change':
      case 'order_status_change_test':
        const status = body.status;
        const order_id = body.order_id;
        if (status === 'chargeable') {
          const appOrderId = `${Date.now()}_${order_id}`;
          return res.json({ response: { order_id: Number(order_id), app_order_id: String(appOrderId) } });
        }
        // paid / cancel / other — acknowledge
        return res.json({ response: 1 });

      case 'get_subscription':
      case 'get_subscription_test':
        const subscritpionId = body.item || body.item_id;
        const subscritpion = SUBSCRIPTIONS_CATALOG[subscritpionId];
        if (!subscritpion) {
          console.warn(`[${VK_PLATFORM}] Invalid subscritpion ${subscritpionId}`);
          return res.json({ error: { error_code: 20, error_msg: 'Subs not found' } });
        }

        return res.json({ response: subscritpion });

      case 'subscription_status_change':
      case 'subscription_status_change_test':
        const subscritionID = body.subscription_id;
        const userId = body.user_id;
        console.debug(`[SUBS STATUS] for ${subscritionID} ${body.status}`)

        return res.json(
          {
            response: {
              "subscription_id": subscritionID,
              "app_order_id": Number(userId + '' + subscritionID)
            }
          }
        );
    }

    // Fallback OK
    return res.json({ response: 1 });
  } catch (e) {
    console.error('[VK PAY] callback error', e);
    return res.status(500).send('server error');
  }
});


function okJsonError(code, msg) {
  // Per docs, error payload shape:
  // { "error_code": <int>, "error_msg": "<text>", "error_data": null }
  return { error_code: code, error_msg: msg, error_data: null };
}

// Endpoint for OK callbacks (OK может вызывать и /api/payments/callback)
app.all('/api/ok/callback/:appId', async (req, res) => {
  try {
    logRequest(OK_PLATFORM, req);
    if (req.method !== 'GET') {
      logError(OK_PLATFORM, 'Invalid method');
      res.set('Invocation-error', '104'); // Using 104 as generic error per docs
      return res.status(405).json(okJsonError(104, 'Only GET is allowed by OK docs'));
    }

    const body = req.method === 'GET' ? req.query : (req.body || {});
    const appId = req.params.appId;
    const appSecret = getAppSecret(appId);

    // signature
    if (!okCheckSig(body, appSecret)) {
      logError(VK_PLATFORM, req, `Sign mismatch`);
      res.set('Invocation-error', '104');
      return res.status(403).json(okJsonError(104, 'PARAM_SIGNATURE : Invalid signature'));
    }

    // required fields (per docs). Some subscription events may lack transaction_id.
    const uid = body.uid;
    const transaction_id = body.transaction_id || '';
    const amount = Number(body.amount || 0);
    const product_code = body.product_code || '';
    const transaction_time = body.transaction_time || '';

    // Optional: validate catalog & price match to prevent tampering
    if (product_code) {
      const isSubscription = +SUBSCRIPTIONS_CATALOG[product_code];
      const product = CATALOG[product_code] || SUBSCRIPTIONS_CATALOG[product_code];
      if (!product) {
        console.warn(`[${VK_PLATFORM}] Invalid product ${product_code}`);
        res.set('Invocation-error', '1001');
        return res.status(400).json(okJsonError(1001, 'CALLBACK_INVALID_PAYMENT : Unknown product_code'));
      }

      if (Number.isFinite(product.price) && amount !== Number(product.price) && !isSubscription) {
        console.warn(`[${VK_PLATFORM}] Invalid amount ${product_code}`);
        res.set('Invocation-error', '1001');
        return res.status(400).json(okJsonError(1001, 'CALLBACK_INVALID_PAYMENT : Amount mismatch'));
      }
    }

    // Success confirmation
    res.type('application/json');
    return res.status(200).send(true);
  } catch (e) {
    console.error('[OK PAY] callback error', e);
    res.set('Invocation-error', '9999');
    return res.status(500).json(okJsonError(9999, 'SYSTEM : server error'));
  }
});

// ===== Static & health =====
app.use(express.static(PUBLIC_DIR,{maxAge:'1h',index:false}));
app.get('/',(req,res)=>res.sendFile(path.join(PUBLIC_DIR,'index.html')));

const PORT=process.env.PORT||8080;
app.listen(PORT,()=>console.log('Server listening on :'+PORT));

// --- ЛОГИРОВАНИЕ РЕКЛАМЫ ---
app.use(express.json()); // если уже есть — второй раз не добавляй

app.post('/log', (req, res) => {
  console.debug('[Log AD]', req.body); // смотри тут всё, что прилетает с клиента
  res.sendStatus(204);
});
