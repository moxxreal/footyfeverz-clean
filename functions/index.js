const functions = require('firebase-functions');
const admin     = require('firebase-admin');
admin.initializeApp();

exports.cleanupExpiredPoke = functions.firestore
  .document('rivalPokes/{pokeId}')
  .onDelete(async (snap, context) => {
    const db     = admin.firestore();
    const pokeId = context.params.pokeId;
    const collections = ['votes', 'supportVotes', 'comments'];

    const deletePromises = collections.map(async (col) => {
      // listDocuments() rather than .get() so we don't pay for reads
      const docs  = await db.collection(`rivalPokes/${pokeId}/${col}`).listDocuments();
      const batch = db.batch();
      docs.forEach(docRef => batch.delete(docRef));
      return batch.commit();
    });

    await Promise.all(deletePromises);
  });
