import http from 'node:http';
import {readFile} from 'node:fs/promises';
import {randomBytes,scrypt as rawScrypt,timingSafeEqual,createHash} from 'node:crypto';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';
import {database} from './db.mjs';
const scrypt=promisify(rawScrypt);const hash=t=>createHash('sha256').update(t).digest('hex');
export async function passwordHash(password){const salt=randomBytes(16).toString('hex');const key=await scrypt(password,salt,64);return salt+':'+key.toString('hex');}
export async function passwordMatches(password,stored){const [salt,key]=stored.split(':');const actual=await scrypt(password,salt,64);const expected=Buffer.from(key,'hex');return expected.length===actual.length&&timingSafeEqual(expected,actual);}
class Failure extends Error{constructor(status,message){super(message);this.status=status;}}
const valid=(yes,message)=>{if(!yes)throw new Failure(400,message);};
const text=(x,min,max,label)=>{valid(typeof x==='string'&&x.trim().length>=min&&x.trim().length<=max,`${label} must contain ${min}–${max} characters.`);return x.trim();};
const email=x=>{const e=text(x,5,254,'Email').toLowerCase();valid(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e),'Enter a valid email address.');return e;};
const password=x=>{valid(typeof x==='string'&&x.length>=10&&x.length<=128,'Password must contain 10–128 characters.');return x;};
const slots=['09:00','10:30','12:00','14:30'];
export async function createApp({db,production=false,origin}={}){
 const store=db||await database({url:process.env.DATABASE_URL,file:process.env.LOCAL_DB||'pawcare.sqlite'});const q=store.query;const limits=new Map();
 const cookie=(value,age)=>`pawcare_session=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${production?'; Secure':''}`;
 const one=async(sql,args=[])=>(await q(sql,args)).rows[0];
 async function current(req){const token=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('pawcare_session='))?.slice(16);if(!token)return null;const row=await one('SELECT u.id,u.email,u.name,u.role,u.phone,u.city,s.csrf FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=$1 AND s.expires>$2',[hash(token),Date.now()]);return row?{...row,token_hash:hash(token)}:null;}
 function throttle(req,group){const ip=req.socket.remoteAddress;const key=group+':'+ip;const now=Date.now();if(limits.size>10000)for(const [k,v] of limits)if(v.until<now)limits.delete(k);let v=limits.get(key);if(!v||v.until<now){v={n:0,until:now+600000};limits.set(key,v);}if(++v.n>30)throw new Failure(429,'Too many attempts. Try again in 10 minutes.');}
 async function body(req){let b='';for await(const chunk of req){b+=chunk; if(Buffer.byteLength(b)>32768)throw new Failure(413,'Request is too large.');}try{return JSON.parse(b||'{}');}catch{throw new Failure(400,'Invalid request data.');}}
 async function session(user,res){const token=randomBytes(32).toString('hex'),csrf=randomBytes(24).toString('hex');await q('INSERT INTO sessions(token_hash,user_id,csrf,expires) VALUES($1,$2,$3,$4)',[hash(token),user.id,csrf,Date.now()+86400000]);res.setHeader('Set-Cookie',cookie(token,86400));return {user:{id:user.id,name:user.name,email:user.email,role:user.role},csrf};}
 async function route(req,res){
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('X-Frame-Options','DENY');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");if(production)res.setHeader('Strict-Transport-Security','max-age=31536000');
  const url=new URL(req.url,'http://localhost');const path=url.pathname;const method=req.method;
  const send=(data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(data));};
  if(method==='GET'&&path==='/health'){await q('SELECT 1');return send({status:'ok'});}
  if(method==='GET'&&!path.startsWith('/api/')){const files={'/':'index.html','/app.js':'app.js','/style.css':'style.css'};if(!files[path])throw new Failure(404,'Page not found.');const content=await readFile(new URL('./public/'+files[path],import.meta.url));res.writeHead(200,{'Content-Type':path.endsWith('.js')?'text/javascript':path.endsWith('.css')?'text/css':'text/html','Cache-Control':'no-cache'});return res.end(content);}
  if(!path.startsWith('/api/'))throw new Failure(404,'Not found.');
  const user=await current(req);let data={};
  if(['POST','PATCH','DELETE'].includes(method)){
   if(!/^application\/json(?:;|$)/i.test(req.headers['content-type']||''))throw new Failure(415,'Use JSON for this request.');
   const expected=origin||process.env.APP_ORIGIN||process.env.RENDER_EXTERNAL_URL||`http://${req.headers.host}`;
   if(req.headers.origin!==expected)throw new Failure(403,'Request origin not allowed.');
   if(user&&req.headers['x-csrf-token']!==user.csrf)throw new Failure(403,'Session verification failed. Refresh and try again.');
   data=await body(req);
  }
  if(path==='/api/register'&&method==='POST'){
   throttle(req,'auth');valid(!user,'Log out before creating another account.');const e=email(data.email),name=text(data.name,2,100,'Full name'),p=password(data.password);const id=store.id();try{await q('INSERT INTO users(id,email,name,password_hash) VALUES($1,$2,$3,$4)',[id,e,name,await passwordHash(p)]);}catch(err){if(err.code==='23505'||err.message?.includes('UNIQUE'))throw new Failure(409,'An account with that email already exists.');throw err;}return send(await session({id,email:e,name,role:'owner'},res),201);
  }
  if(path==='/api/login'&&method==='POST'){
   throttle(req,'auth');const e=email(data.email),p=password(data.password);const row=await one('SELECT * FROM users WHERE email=$1',[e]);const dummy='00000000000000000000000000000000:'+('00'.repeat(64));const ok=await passwordMatches(p,row?.password_hash||dummy);if(!row||!ok)throw new Failure(401,'Email or password is incorrect.');if(user)await q('DELETE FROM sessions WHERE token_hash=$1',[user.token_hash]);return send(await session(row,res));
  }
  if(path==='/api/session'&&method==='GET')return send(user?{user:{id:user.id,name:user.name,email:user.email,role:user.role,phone:user.phone,city:user.city},csrf:user.csrf}:{user:null});
  if(path==='/api/vets'&&method==='GET')return send({vets:(await q('SELECT * FROM vets WHERE active=1 ORDER BY name')).rows});
  if(!user)throw new Failure(401,'Please log in to continue.');
  if(path==='/api/logout'&&method==='POST'){await q('DELETE FROM sessions WHERE token_hash=$1',[user.token_hash]);res.setHeader('Set-Cookie',cookie('',0));return send({ok:true});}
  if(path==='/api/profile'&&method==='PATCH'){const name=text(data.name,2,100,'Full name'),phone=text(data.phone||'',0,25,'Phone'),city=text(data.city||'',0,100,'City');valid(!phone||/^[+\d ()-]{7,25}$/.test(phone),'Enter a valid phone number.');await q('UPDATE users SET name=$1,phone=$2,city=$3 WHERE id=$4',[name,phone,city,user.id]);return send({ok:true});}
  if(path==='/api/password'&&method==='POST'){throttle(req,'password');const row=await one('SELECT password_hash FROM users WHERE id=$1',[user.id]);if(!await passwordMatches(password(data.current),row.password_hash))throw new Failure(401,'Current password is incorrect.');await q('UPDATE users SET password_hash=$1 WHERE id=$2',[await passwordHash(password(data.next)),user.id]);await q('DELETE FROM sessions WHERE user_id=$1',[user.id]);res.setHeader('Set-Cookie',cookie('',0));return send({ok:true});}
  if(path==='/api/pets'&&method==='GET')return send({pets:(await q('SELECT * FROM pets WHERE owner_id=$1 ORDER BY name',[user.id])).rows});
  if((path==='/api/pets'&&method==='POST')||(path.startsWith('/api/pets/')&&method==='PATCH')){
   const name=text(data.name,1,60,'Pet name'),species=data.species,breed=text(data.breed,1,80,'Breed'),dob=data.dob,notes=text(data.notes||'',0,1000,'Notes');valid(['Dog','Cat','Other'].includes(species),'Choose a supported species.');valid(/^\d{4}-\d{2}-\d{2}$/.test(dob)&&!isNaN(Date.parse(dob))&&new Date(dob).toISOString().slice(0,10)===dob&&dob<=new Date().toISOString().slice(0,10),'Enter a valid birth date in the past.');
   if(method==='POST'){const id=store.id();await q('INSERT INTO pets(id,owner_id,name,species,breed,dob,notes) VALUES($1,$2,$3,$4,$5,$6,$7)',[id,user.id,name,species,breed,dob,notes]);return send({id},201);}
   const row=await one('UPDATE pets SET name=$1,species=$2,breed=$3,dob=$4,notes=$5 WHERE id=$6 AND owner_id=$7 RETURNING id',[name,species,breed,dob,notes,path.split('/').pop(),user.id]);if(!row)throw new Failure(404,'Pet not found.');return send({ok:true});
  }
  if(path==='/api/availability'&&method==='GET'){const vet=url.searchParams.get('vet'),date=url.searchParams.get('date');const taken=(await q("SELECT time FROM appointments WHERE vet_id=$1 AND date=$2 AND status IN ('requested','confirmed')",[vet,date])).rows.map(x=>x.time);return send({times:slots.filter(t=>!taken.includes(t))});}
  if(path==='/api/appointments'&&method==='GET'){const admin=user.role==='admin';const sql=`SELECT a.*,p.name AS pet_name,v.name AS vet_name,v.clinic,v.fee,u.name AS owner_name FROM appointments a JOIN pets p ON p.id=a.pet_id JOIN vets v ON v.id=a.vet_id JOIN users u ON u.id=a.owner_id ${admin?'':'WHERE a.owner_id=$1'} ORDER BY a.date DESC,a.time`;return send({appointments:(await q(sql,admin?[]:[user.id])).rows});}
  if(path==='/api/appointments'&&method==='POST'){
   throttle(req,'book');const pet=await one('SELECT id FROM pets WHERE id=$1 AND owner_id=$2',[data.pet_id,user.id]),vet=await one('SELECT id FROM vets WHERE id=$1 AND active=1',[data.vet_id]);valid(pet&&vet,'Select your pet and an available veterinarian.');const date=data.date,time=data.time;valid(typeof date==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(date)&&!isNaN(Date.parse(date))&&new Date(date).toISOString().slice(0,10)===date&&date>new Date().toISOString().slice(0,10),'Choose a date from tomorrow onward.');valid(date<=new Date(Date.now()+90*86400000).toISOString().slice(0,10),'Book within the next 90 days.');valid(slots.includes(time),'Select an available time.');const reason=text(data.reason,5,500,'Reason');const id=store.id();try{await q('INSERT INTO appointments(id,owner_id,pet_id,vet_id,date,time,reason,created) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',[id,user.id,pet.id,vet.id,date,time,reason,Date.now()]);}catch(err){if(err.code==='23505'||err.message?.includes('UNIQUE'))throw new Failure(409,'That time has just been booked. Choose another slot.');throw err;}return send({id},201);
  }
  if(path.startsWith('/api/appointments/')&&method==='PATCH'){
   const id=path.split('/').pop(),status=data.status;const row=await one('SELECT * FROM appointments WHERE id=$1',[id]);if(!row||(row.owner_id!==user.id&&user.role!=='admin'))throw new Failure(404,'Appointment not found.');
   const next={requested:['confirmed','declined','cancelled'],confirmed:['completed','cancelled'],completed:[],cancelled:[],declined:[]};if(user.role!=='admin'&&status!=='cancelled')throw new Failure(403,'Clinic access required.');valid(next[row.status].includes(status),'This appointment cannot make that status change.');const changed=await one('UPDATE appointments SET status=$1 WHERE id=$2 AND status=$3 RETURNING id',[status,id,row.status]);if(!changed)throw new Failure(409,'Appointment changed. Refresh and try again.');return send({ok:true});
  }
  throw new Failure(404,'Not found.');
 }
 const server=http.createServer((req,res)=>route(req,res).catch(err=>{if(res.headersSent)return res.end();const status=err.status||503;res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({error:err.status?err.message:'The service is temporarily unavailable. Please try again.'}));if(!err.status)console.error(JSON.stringify({event:'request_failed',code:err.code||'internal',path:new URL(req.url,'http://local').pathname}));}));server.requestTimeout=15000;server.headersTimeout=10000;return {server,db:store};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){if(process.env.NODE_ENV==='production'&&!process.env.DATABASE_URL)throw new Error('DATABASE_URL is required in production.');const {server}=await createApp({production:process.env.NODE_ENV==='production'});server.listen(Number(process.env.PORT)||3000,'0.0.0.0',()=>console.log('PawCare server ready'));}
