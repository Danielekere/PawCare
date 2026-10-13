// Render makes DATABASE_URL available to builds; exercise PostgreSQL in an
// isolated temporary schema without changing application records.
if(process.env.RENDER==='true'&&process.env.DATABASE_URL)await import('./check-neon.mjs');
