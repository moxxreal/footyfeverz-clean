// generate-vapid.js
const webpush = require('web-push');

const keys = webpush.generateVAPIDKeys();

console.log('Public VAPID Key:', keys.publicKey);
console.log('Private VAPID Key:', keys.privateKey);
