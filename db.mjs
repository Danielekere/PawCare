import {DatabaseSync} from 'node:sqlite';
import {randomUUID} from 'node:crypto';
export async function database(config={}) {
 let pg,sqlite;
 if(config.url){const {Pool}=await import('pg');const u=new URL(config.url);for(const k of ['sslmode','sslcert','sslkey','sslrootcert'])u.searchParams.delete(k);pg=new Pool({connectionString:u.toString(),ssl:{rejectUnauthorized:true},max:5,connectionTimeoutMillis:10000,statement_timeout:10000});}
 else {sqlite=new DatabaseSync(config.file||':memory:');sqlite.exec('PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;');}
 const query=async(sql,args=[])=>{
  if(pg)return pg.query(sql,args);
  // Reorder repeated PostgreSQL parameters for SQLite's positional bindings.
  const bindings=[];const local=sql.replace(/\$(\d+)/g,(_,i)=>{bindings.push(args[Number(i)-1]);return '?';});
  const stmt=sqlite.prepare(local);return {rows:stmt.all(...bindings)};
 };
 const schema=[
 `CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'owner' CHECK(role IN ('owner','admin')),phone TEXT NOT NULL DEFAULT '',city TEXT NOT NULL DEFAULT '')`,
 `CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf TEXT NOT NULL,expires BIGINT NOT NULL)`,
 `CREATE TABLE IF NOT EXISTS pets(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES users(id),name TEXT NOT NULL,species TEXT NOT NULL CHECK(species IN ('Dog','Cat','Other')),breed TEXT NOT NULL,dob TEXT NOT NULL,notes TEXT NOT NULL DEFAULT '')`,
 `CREATE TABLE IF NOT EXISTS vets(id TEXT PRIMARY KEY,name TEXT NOT NULL,specialty TEXT NOT NULL,clinic TEXT NOT NULL,fee INTEGER NOT NULL CHECK(fee>=0),active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)))`,
 `CREATE TABLE IF NOT EXISTS appointments(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES users(id),pet_id TEXT NOT NULL REFERENCES pets(id),vet_id TEXT NOT NULL REFERENCES vets(id),date TEXT NOT NULL,time TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'requested' CHECK(status IN ('requested','confirmed','completed','cancelled','declined')),created BIGINT NOT NULL)`,
 `CREATE UNIQUE INDEX IF NOT EXISTS appointment_slot ON appointments(vet_id,date,time) WHERE status IN ('requested','confirmed')`,
 `CREATE INDEX IF NOT EXISTS pet_owner ON pets(owner_id)`,
 `CREATE INDEX IF NOT EXISTS appointment_owner ON appointments(owner_id)`,
 `CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires)`];
 for(const sql of schema)await query(sql);
 // Public teaching-clinic data is marked as sample content in the interface.
 for(const v of [['sample-amara','Dr. Amara Okafor','General practice','Sample Companion Care Clinic',12000],['sample-tunde','Dr. Tunde Adebayo','Preventive care','Sample Paws & Wellness Clinic',10000],['sample-zainab','Dr. Zainab Bello','Small-animal care','Sample Animal Care Clinic',15000]])await query('INSERT INTO vets(id,name,specialty,clinic,fee) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING',v);
 return {query,close:async()=>pg?pg.end():sqlite.close(),id:randomUUID};
}
