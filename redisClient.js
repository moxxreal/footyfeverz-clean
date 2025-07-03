// redisClient.js
const { createClient } = require('redis');

const client = createClient({
  // if you have a REDIS_URL in your .env, e.g. redis://localhost:6379
  url: process.env.REDIS_URL || 'redis://127.0.0.1:6379'
});

client.on('error', err => {
  console.error('Redis Client Error', err);
});

(async () => {
  await client.connect();
  console.log('✅ Connected to Redis');
})();

module.exports = client;
