const express=require('express');
const path=require('path');
const session=require('express-session');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');

const app=express();
const PORT=process.env.PORT||3000;
const dataDir=process.env.RAILWAY_VOLUME_MOUNT_PATH || process.env.DATA_DIR || __dirname;
const dbFile=process.env.DB_FILE || path.join(dataDir,'goodsflow.db');
const db=new Database(dbFile);

db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 sku TEXT UNIQUE NOT NULL,
 category TEXT,
 cost REAL NOT NULL DEFAULT 0,
 price REAL NOT NULL DEFAULT 0,
 stock INTEGER NOT NULL DEFAULT 0,
 reorder INTEGER NOT NULL DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sales(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 product_id INTEGER NOT NULL,
 qty INTEGER NOT NULL,
 total REAL NOT NULL,
 sale_date TEXT NOT NULL,
 FOREIGN KEY(product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS suppliers(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 company TEXT NOT NULL,
 contact TEXT,
 phone TEXT,
 category TEXT
);`);

if(!db.prepare('SELECT id FROM users LIMIT 1').get()){
  const adminEmail=process.env.ADMIN_EMAIL;
  const adminPassword=process.env.ADMIN_PASSWORD;
  if(!adminEmail || !adminPassword){
    console.error('ADMIN_EMAIL and ADMIN_PASSWORD must be set before first production start.');
    process.exit(1);
  }
  const hash=bcrypt.hashSync(adminPassword,12);
  db.prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)')
    .run(process.env.BUSINESS_NAME||'Brodrick',adminEmail.toLowerCase().trim(),hash);
}
if(!db.prepare('SELECT id FROM products LIMIT 1').get()){
  const ins=db.prepare('INSERT INTO products(name,sku,category,cost,price,stock,reorder) VALUES(?,?,?,?,?,?,?)');
  ins.run('Solar Lantern','SL-001','Lighting',1800,2500,34,10);
  ins.run('LED Bulb 12W','LB-012','Electrical',180,300,8,15);
  ins.run('Rechargeable Fan','RF-004','Appliances',3200,4500,19,8);
}

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
  secret:process.env.SESSION_SECRET||(()=>{throw new Error('SESSION_SECRET must be set in production')})(),
  resave:false,saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000}
}));
app.use(express.static(path.join(__dirname,'public')));

function auth(req,res,next){if(!req.session.user)return res.status(401).json({error:'Not authenticated'});next();}

app.post('/api/login',(req,res)=>{
  const u=db.prepare('SELECT * FROM users WHERE email=?').get((req.body.email||'').toLowerCase().trim());
  if(!u||!bcrypt.compareSync(req.body.password||'',u.password_hash)) return res.status(401).json({error:'Invalid email or password'});
  req.session.user={id:u.id,name:u.name,email:u.email};
  res.json(req.session.user);
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',(req,res)=>res.json(req.session.user||null));
app.get('/health',(req,res)=>res.json({ok:true,service:'GoodsFlow'}));

app.get('/api/dashboard',auth,(req,res)=>{
  const inventory=db.prepare('SELECT COALESCE(SUM(cost*stock),0) value FROM products').get().value;
  const products=db.prepare('SELECT COUNT(*) n FROM products').get().n;
  const low=db.prepare('SELECT COUNT(*) n FROM products WHERE stock<=reorder').get().n;
  const today=new Date().toISOString().slice(0,10);
  const sales=db.prepare('SELECT COALESCE(SUM(total),0) total FROM sales WHERE sale_date=?').get(today).total;
  res.json({inventory,products,low,sales});
});

app.get('/api/products',auth,(req,res)=>res.json(db.prepare('SELECT * FROM products ORDER BY id DESC').all()));
app.post('/api/products',auth,(req,res)=>{
  try{
    const p=req.body;
    const r=db.prepare('INSERT INTO products(name,sku,category,cost,price,stock,reorder) VALUES(?,?,?,?,?,?,?)')
      .run(p.name,p.sku,p.category||'',+p.cost||0,+p.price||0,+p.stock||0,+p.reorder||0);
    res.json(db.prepare('SELECT * FROM products WHERE id=?').get(r.lastInsertRowid));
  }catch(e){res.status(400).json({error:e.message})}
});
app.put('/api/products/:id',auth,(req,res)=>{
  const p=req.body;
  db.prepare('UPDATE products SET name=?,sku=?,category=?,cost=?,price=?,stock=?,reorder=? WHERE id=?')
    .run(p.name,p.sku,p.category||'',+p.cost||0,+p.price||0,+p.stock||0,+p.reorder||0,req.params.id);
  res.json({ok:true});
});
app.delete('/api/products/:id',auth,(req,res)=>{
  db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);res.json({ok:true});
});
app.post('/api/products/:id/stock',auth,(req,res)=>{
  db.prepare('UPDATE products SET stock=? WHERE id=?').run(Math.max(0,+req.body.stock||0),req.params.id);res.json({ok:true});
});

app.get('/api/sales',auth,(req,res)=>res.json(db.prepare(`
SELECT sales.*,products.name product FROM sales JOIN products ON products.id=sales.product_id ORDER BY sales.id DESC`).all()));
app.post('/api/sales',auth,(req,res)=>{
  const p=db.prepare('SELECT * FROM products WHERE id=?').get(req.body.product_id);
  const qty=+req.body.qty;
  if(!p||!Number.isInteger(qty)||qty<1||qty>p.stock)return res.status(400).json({error:'Invalid quantity or insufficient stock'});
  const total=qty*p.price, date=new Date().toISOString().slice(0,10);
  const tx=db.transaction(()=>{
    db.prepare('UPDATE products SET stock=stock-? WHERE id=?').run(qty,p.id);
    db.prepare('INSERT INTO sales(product_id,qty,total,sale_date) VALUES(?,?,?,?)').run(p.id,qty,total,date);
  });
  tx();res.json({ok:true,total});
});

app.get('/api/suppliers',auth,(req,res)=>res.json(db.prepare('SELECT * FROM suppliers ORDER BY id DESC').all()));
app.post('/api/suppliers',auth,(req,res)=>{
  const r=db.prepare('INSERT INTO suppliers(company,contact,phone,category) VALUES(?,?,?,?)')
    .run(req.body.company,req.body.contact||'',req.body.phone||'',req.body.category||'');
  res.json(db.prepare('SELECT * FROM suppliers WHERE id=?').get(r.lastInsertRowid));
});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

if(!process.env.SESSION_SECRET) throw new Error('SESSION_SECRET must be set in production');
app.listen(PORT,'0.0.0.0',()=>console.log(`GoodsFlow online portal running on port ${PORT}`));
