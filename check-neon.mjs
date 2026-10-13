// Accept the secret connection URL via stdin, never through command arguments.
import {Pool} from 'pg';import {spawnSync} from 'node:child_process';import {randomBytes} from 'node:crypto';import {createInterface} from 'node:readline';
let input=process.env.DATABASE_URL;
if(!input){if(process.stdin.isTTY)spawnSync('stty',['-echo'],{stdio:'inherit'});console.log('Ready for private database URL on stdin.');const reader=createInterface({input:process.stdin});input=await new Promise(r=>reader.once('line',r));reader.close();if(process.stdin.isTTY)spawnSync('stty',['echo'],{stdio:'inherit'});}
const connectionString=input.trim();let u;try{u=new URL(connectionString);}catch{console.log('Database URL was invalid.');process.exit(1);}for(const k of ['sslmode','sslcert','sslkey','sslrootcert'])u.searchParams.delete(k);
// Temporary-schema tests require a session-level search_path. Neon’s
// transaction pooler does not accept that startup parameter; use its direct
// endpoint for this isolated test only. The application stays pooled.
if(u.hostname.endsWith('.neon.tech'))u.hostname=u.hostname.replace(/-pooler(?=\.)/,'');
const pool=new Pool({connectionString:u.toString(),ssl:{rejectUnauthorized:true},max:2,connectionTimeoutMillis:10000});const schema='pawcare_test_'+randomBytes(6).toString('hex');
try{await pool.query('SELECT 1');await pool.query('CREATE SCHEMA '+schema);u.searchParams.set('options','-csearch_path='+schema);const r=spawnSync(process.execPath,['--test','test/app.test.mjs'],{env:{...process.env,PAWCARE_TEST_DATABASE_URL:u.toString()},encoding:'utf8'});process.stdout.write(r.stdout);if(r.status!==0){process.stdout.write('PostgreSQL integration suite failed.\n');process.exitCode=1;}else process.stdout.write('Live Neon/PostgreSQL integration suite passed.\n');}
catch(e){process.stdout.write('Neon check failed: '+(e.code||e.name)+'\n');process.exitCode=1;}
finally{await pool.query('DROP SCHEMA IF EXISTS '+schema+' CASCADE').catch(()=>{});await pool.end();}
