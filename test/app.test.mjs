import test from 'node:test';import assert from 'node:assert/strict';import {database} from '../db.mjs';import {createApp} from '../server.mjs';
test('Authentication, ownership, CSRF, booking constraints and clinic roles',async()=>{
 const testOrigin='http://pawcare-test.local';const db=await database({url:process.env.PAWCARE_TEST_DATABASE_URL}),{server}=await createApp({db,origin:testOrigin});await new Promise(r=>server.listen(0,'127.0.0.1',r));const root='http://127.0.0.1:'+server.address().port;
 async function request(path,{method='GET',data,client,origin=testOrigin,csrf=true}={}){const res=await fetch(root+path,{method,headers:{'Content-Type':'application/json',Origin:origin,...(client?{Cookie:client.cookie,...(csrf?{'X-CSRF-Token':client.csrf}:{})}:{})},...(data?{body:JSON.stringify(data)}:{})});return {status:res.status,body:await res.json(),cookie:res.headers.get('set-cookie')};}
 async function register(email){const r=await request('/api/register',{method:'POST',data:{email,name:'Test Owner',password:'secure-passphrase-123'}});assert.equal(r.status,201);return {cookie:r.cookie.split(';')[0],csrf:r.body.csrf,id:r.body.user.id};}
 try{
  assert.equal((await request('/health')).status,200);
  const owner=await register('owner@example.com'),other=await register('other@example.com');
  const user=(await db.query('SELECT password_hash FROM users WHERE id=$1',[owner.id])).rows[0];assert(!user.password_hash.includes('secure-passphrase'));
  const login=await request('/api/login',{method:'POST',data:{email:'owner@example.com',password:'wrong-password-123'}});assert.equal(login.status,401);
  assert.equal((await request('/api/pets')).status,401);
  assert.equal((await request('/api/pets',{method:'POST',client:owner,csrf:false,data:{}})).status,403);
  assert.equal((await request('/api/pets',{method:'POST',client:owner,origin:'https://attacker.example',data:{}})).status,403);
  assert.equal((await request('/api/pets',{method:'POST',client:owner,data:{name:'Milo',species:'Dog',breed:'Retriever',dob:'2023-02-31'}})).status,400);
  const created=await request('/api/pets',{method:'POST',client:owner,data:{name:'Milo',species:'Dog',breed:'Retriever',dob:'2023-07-12',notes:'<script>alert(1)</script>'}});assert.equal(created.status,201);const pet=created.body.id;
  assert.equal((await request('/api/pets',{client:other})).body.pets.length,0);
  assert.equal((await request('/api/pets/'+pet,{method:'PATCH',client:other,data:{name:'Stolen',species:'Dog',breed:'Retriever',dob:'2023-07-12'}})).status,404);
  const date=new Date(Date.now()+2*86400000).toISOString().slice(0,10),booking={pet_id:pet,vet_id:'sample-amara',date,time:'10:30',reason:'Annual wellness check'};
  assert.equal((await request('/api/appointments',{method:'POST',client:other,data:booking})).status,400);
  const booked=await request('/api/appointments',{method:'POST',client:owner,data:booking});assert.equal(booked.status,201);
  assert.equal((await request('/api/appointments',{method:'POST',client:owner,data:booking})).status,409);
  assert(!(await request('/api/availability?vet=sample-amara&date='+date,{client:owner})).body.times.includes('10:30'));
  assert.equal((await request('/api/appointments',{client:other})).body.appointments.length,0);
  assert.equal((await request('/api/appointments/'+booked.body.id,{method:'PATCH',client:other,data:{status:'cancelled'}})).status,404);
  assert.equal((await request('/api/appointments/'+booked.body.id,{method:'PATCH',client:owner,data:{status:'confirmed'}})).status,403);
  // Operator provisioning, never a user-controlled signup field.
  await db.query("UPDATE users SET role='admin' WHERE id=$1",[other.id]);
  assert.equal((await request('/api/appointments/'+booked.body.id,{method:'PATCH',client:other,data:{status:'confirmed'}})).status,200);
  assert.equal((await request('/api/appointments/'+booked.body.id,{method:'PATCH',client:owner,data:{status:'cancelled'}})).status,200);
  assert.equal((await request('/api/appointments/'+booked.body.id,{method:'PATCH',client:other,data:{status:'confirmed'}})).status,400);
  assert.equal((await request('/api/appointments',{method:'POST',client:owner,data:booking})).status,201);
  assert.equal((await request('/api/profile',{method:'PATCH',client:owner,data:{name:"Robert'); DROP TABLE users;--",city:'Lagos',phone:'08012345678',role:'admin'}})).status,200);
  const profile=(await request('/api/session',{client:owner})).body.user;assert.equal(profile.role,'owner');assert(profile.name.includes('DROP TABLE'));
  assert.equal((await request('/api/password',{method:'POST',client:owner,data:{current:'secure-passphrase-123',next:'another-safe-passphrase'}})).status,200);
  assert.equal((await request('/api/session',{client:owner})).body.user,null);
  const newLogin=await request('/api/login',{method:'POST',data:{email:'owner@example.com',password:'another-safe-passphrase'}});assert.equal(newLogin.status,200);
  const active={cookie:newLogin.cookie.split(';')[0],csrf:newLogin.body.csrf};assert.equal((await request('/api/logout',{method:'POST',client:active,data:{}})).status,200);assert.equal((await request('/api/session',{client:active})).body.user,null);
 }finally{await new Promise(r=>server.close(r));await db.close();}
});
