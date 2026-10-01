require('dotenv').config();
const express=require('express'),{Pool}=require('pg'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const rateLimit=require('express-rate-limit'),helmet=require('helmet');
const db=new Pool({connectionString:process.env.DATABASE_URL}),SECRET=process.env.JWT_SECRET;
if(!SECRET)throw new Error('JWT_SECRET required');
const SYMBOLS=['BTCUSDT','ETHUSDT','BNBUSDT'],app=express();
app.use(helmet({contentSecurityPolicy:false}));app.use(express.json());
const lim=rateLimit({windowMs:15*60*1000,limit:30});
const h=f=>(q,s)=>f(q,s).catch(e=>s.status(400).json({error:e.message}));
const sign=id=>jwt.sign({id},SECRET,{expiresIn:'12h'});
const num=(v,min,max)=>{v=Number(v);if(!(v>=min&&v<=max))throw new Error('Amount out of range');return v};
async function tx(fn){const c=await db.connect();try{await c.query('BEGIN');const r=await fn(c);await c.query('COMMIT');return r}catch(e){await c.query('ROLLBACK');throw e}finally{c.release()}}
// every balance change goes through here -> ledger row (audit trail)
async function post(c,uid,type,amt,o={}){const r=await c.query('UPDATE users SET balance=balance+$2 WHERE id=$1 RETURNING balance',[uid,amt]);
 await c.query('INSERT INTO ledger(user_id,type,amount,balance_after,ref,note,actor_id) VALUES($1,$2,$3,$4,$5,$6,$7)',[uid,type,amt,r.rows[0].balance,o.ref,o.note,o.actor]);}
const payoutPct=async()=>Number((await db.query("SELECT value FROM settings WHERE key='default_payout'")).rows[0].value);
async function price(sym){const r=await fetch('https://api.binance.com/api/v3/ticker/price?symbol='+sym);if(!r.ok)throw new Error('Price feed unavailable');return Number((await r.json()).price)}
const auth=role=>async(q,s,n)=>{try{const p=jwt.verify((q.headers.authorization||'').slice(7),SECRET);
 const u=(await db.query('SELECT id,email,role,balance,active FROM users WHERE id=$1',[p.id])).rows[0];
 if(!u||!u.active||(role&&u.role!==role))return s.sendStatus(403);q.user=u;n()}catch{s.sendStatus(401)}};

app.post('/api/register',lim,h(async(q,s)=>{const{email,password}=q.body;
 if(!/^\S+@\S+$/.test(email)||!password||password.length<8)throw new Error('Valid email and 8+ character password required');
 const r=await db.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id',[email.toLowerCase(),await bcrypt.hash(password,12)]);s.json({token:sign(r.rows[0].id)})}));
app.post('/api/login',lim,h(async(q,s)=>{const u=(await db.query('SELECT * FROM users WHERE email=$1',[String(q.body.email).toLowerCase()])).rows[0];
 if(!u||!u.active||!await bcrypt.compare(String(q.body.password),u.password_hash))throw new Error('Invalid credentials');s.json({token:sign(u.id),role:u.role})}));
app.get('/api/me',auth(),h(async(q,s)=>{s.json({user:q.user,payout:await payoutPct(),
 trades:(await db.query('SELECT * FROM trades WHERE user_id=$1 ORDER BY id DESC LIMIT 50',[q.user.id])).rows})}));
app.get('/api/wallet',auth(),h(async(q,s)=>{const u=q.user.id;s.json({
 ledger:(await db.query('SELECT * FROM ledger WHERE user_id=$1 ORDER BY id DESC LIMIT 50',[u])).rows,
 requests:(await db.query('SELECT * FROM requests WHERE user_id=$1 ORDER BY id DESC LIMIT 50',[u])).rows})}));

// ---- trading: stake locked at open, settled at expiry vs real price, payout rate snapshotted ----
app.post('/api/trades',auth(),h(async(q,s)=>{const{symbol,direction}=q.body,amount=num(q.body.amount,1,1000);
 if(!SYMBOLS.includes(symbol)||!['call','put'].includes(direction))throw new Error('Invalid trade');
 const op=await price(symbol),pp=await payoutPct();
 s.json({id:await tx(async c=>{const r=await c.query("INSERT INTO trades(user_id,symbol,direction,amount,payout_pct,open_price,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '60 seconds') RETURNING id",[q.user.id,symbol,direction,amount,pp,op]);
  await post(c,q.user.id,'trade_stake',-amount,{ref:'trade:'+r.rows[0].id});return r.rows[0].id})})}));
let busy=false;
async function settle(){if(busy)return;busy=true;try{await tx(async c=>{
 const{rows}=await c.query("SELECT * FROM trades WHERE status='open' AND expires_at<=now() ORDER BY id LIMIT 20 FOR UPDATE SKIP LOCKED");
 for(const t of rows){const cp=await price(t.symbol),o=Number(t.open_price);
  const res=cp===o?'tie':((cp>o)===(t.direction==='call')?'win':'loss');
  const pay=res==='win'?+(Number(t.amount)*(1+Number(t.payout_pct)/100)).toFixed(2):res==='tie'?Number(t.amount):0;
  await c.query("UPDATE trades SET status='closed',close_price=$2,result=$3,payout=$4 WHERE id=$1",[t.id,cp,res,pay]);
  if(pay>0)await post(c,t.user_id,'trade_'+res,pay,{ref:'trade:'+t.id})}})}catch(e){console.error('settle:',e.message)}finally{busy=false}}
setInterval(settle,1000);

// ---- wallet ----
app.post('/api/deposits',auth(),h(async(q,s)=>{const{method,txid}=q.body;if(!txid)throw new Error('TxID/reference required');
 await db.query("INSERT INTO requests(user_id,kind,method,amount,txid) VALUES($1,'deposit',$2,$3,$4)",[q.user.id,String(method),num(q.body.amount,1,1e6),String(txid)]);s.json({ok:1})}));
app.post('/api/withdrawals',auth(),h(async(q,s)=>{const amt=num(q.body.amount,1,1e6);if(!q.body.account)throw new Error('Account/address required');
 await tx(async c=>{const r=await c.query("INSERT INTO requests(user_id,kind,method,amount,account) VALUES($1,'withdrawal',$2,$3,$4) RETURNING id",[q.user.id,String(q.body.method),amt,String(q.body.account)]);
  await post(c,q.user.id,'withdrawal_hold',-amt,{ref:'req:'+r.rows[0].id})});s.json({ok:1})}));
app.post('/api/deposits/crypto',auth(),h(async(q,s)=>{const amt=num(q.body.amount,10,1e6);
 const oid='dep-'+crypto.randomUUID();
 await db.query("INSERT INTO requests(user_id,kind,method,amount,external_id) VALUES($1,'deposit','nowpayments',$2,$3)",[q.user.id,amt,oid]);
 const r=await fetch('https://api.nowpayments.io/v1/invoice',{method:'POST',headers:{'x-api-key':process.env.NOWPAYMENTS_API_KEY,'Content-Type':'application/json'},
  body:JSON.stringify({price_amount:amt,price_currency:'usd',order_id:oid,ipn_callback_url:process.env.BASE_URL+'/api/ipn/nowpayments',success_url:process.env.BASE_URL})});
 const j=await r.json();if(!j.invoice_url)throw new Error('Payment provider error');s.json({url:j.invoice_url})}));
const sortObj=o=>Object.keys(o).sort().reduce((a,k)=>(a[k]=o[k]&&typeof o[k]==='object'?sortObj(o[k]):o[k],a),{});
app.post('/api/ipn/nowpayments',h(async(q,s)=>{
 const sig=crypto.createHmac('sha512',process.env.NOWPAYMENTS_IPN_SECRET||'x').update(JSON.stringify(sortObj(q.body))).digest('hex');
 if(sig!==q.get('x-nowpayments-sig'))return s.sendStatus(401);
 if(q.body.payment_status==='finished')await tx(async c=>{
  const r=(await c.query("SELECT * FROM requests WHERE external_id=$1 AND status='pending' FOR UPDATE",[q.body.order_id])).rows[0];
  if(r){await c.query("UPDATE requests SET status='approved',txid=$2,reviewed_at=now() WHERE id=$1",[r.id,String(q.body.payment_id)]);
   await post(c,r.user_id,'deposit',Number(r.amount),{ref:'req:'+r.id,note:'nowpayments'})}});
 s.sendStatus(200)}));

// ---- admin ----
const A=auth('admin');
app.get('/api/admin/users',A,h(async(q,s)=>s.json((await db.query('SELECT id,email,role,balance,active,created_at FROM users ORDER BY id DESC LIMIT 200')).rows)));
app.post('/api/admin/users/:id/balance',A,h(async(q,s)=>{const a=num(q.body.amount,-1e6,1e6);if(!q.body.note)throw new Error('Note required');
 await tx(c=>post(c,q.params.id,'admin_adjust',a,{note:q.body.note,actor:q.user.id}));s.json({ok:1})}));
app.post('/api/admin/users/:id/active',A,h(async(q,s)=>{await db.query('UPDATE users SET active=$2 WHERE id=$1 AND role<>\'admin\'',[q.params.id,!!q.body.active]);s.json({ok:1})}));
app.get('/api/admin/trades',A,h(async(q,s)=>s.json((await db.query('SELECT t.*,u.email FROM trades t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 200')).rows)));
app.get('/api/admin/ledger',A,h(async(q,s)=>s.json((await db.query('SELECT l.*,u.email FROM ledger l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 200')).rows)));
app.get('/api/admin/requests',A,h(async(q,s)=>s.json((await db.query("SELECT r.*,u.email FROM requests r JOIN users u ON u.id=r.user_id WHERE r.status='pending' AND r.method<>'nowpayments' ORDER BY r.id")).rows)));
app.post('/api/admin/requests/:id/:action',A,h(async(q,s)=>{const ok=q.params.action==='approve';if(!ok&&q.params.action!=='reject')throw new Error('Bad action');
 await tx(async c=>{const r=(await c.query("SELECT * FROM requests WHERE id=$1 AND status='pending' FOR UPDATE",[q.params.id])).rows[0];if(!r)throw new Error('Not pending');
  await c.query('UPDATE requests SET status=$2,reviewed_by=$3,reviewed_at=now() WHERE id=$1',[r.id,ok?'approved':'rejected',q.user.id]);
  if(r.kind==='deposit'&&ok)await post(c,r.user_id,'deposit',Number(r.amount),{ref:'req:'+r.id,actor:q.user.id});
  if(r.kind==='withdrawal'&&!ok)await post(c,r.user_id,'withdrawal_refund',Number(r.amount),{ref:'req:'+r.id,actor:q.user.id})});s.json({ok:1})}));
app.get('/api/admin/settings',A,h(async(q,s)=>s.json({default_payout:await payoutPct()})));
app.post('/api/admin/settings',A,h(async(q,s)=>{await db.query("UPDATE settings SET value=$1 WHERE key='default_payout'",[num(q.body.default_payout,50,95)]);s.json({ok:1})}));

app.get('/admin',(q,s)=>s.sendFile(path.join(__dirname,'public/admin.html')));
app.use(express.static(path.join(__dirname,'public')));
(async()=>{await db.query(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));
 if(process.env.ADMIN_EMAIL&&process.env.ADMIN_PASSWORD)await db.query("INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin') ON CONFLICT(email) DO NOTHING",[process.env.ADMIN_EMAIL.toLowerCase(),await bcrypt.hash(process.env.ADMIN_PASSWORD,12)]);
 app.listen(process.env.PORT||3000,()=>console.log('up'))})();
