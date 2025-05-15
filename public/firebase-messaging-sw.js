// public/firebase-messaging-sw.js
importScripts('https://www.gstatic.com/firebasejs/10.11.0/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.11.0/firebase-messaging-compat.js');

firebase.initializeApp({
  apiKey: "AIzaSyDS433ffk_aUkeuINqcVfH3Ti9uhUMVjJ4",
  authDomain: "footyfeverz-31319.firebaseapp.com",
  projectId: "footyfeverz-31319",
  storageBucket: "footyfeverz-31319.firebasestorage.app",
  messagingSenderId: "711628126301",
  appId: "1:711628126301:web:569c8db35ab0b1d5cdb5b4",
  measurementId: "G-SFPWD59N9K"
});

const messaging = firebase.messaging();

messaging.onBackgroundMessage(function(payload) {
  console.log('[Service Worker] Received background message ', payload);
  const { title, body } = payload.notification;

  self.registration.showNotification(title, {
    body,
    icon: '/images/favicon.png'
  });
});
