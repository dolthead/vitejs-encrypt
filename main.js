// import './style.css';

// Usage
const password = 'user-password';
const data = 'Sensitive PII data';

encryptAndStoreData(password, data).then(() => {
  console.log('Data encrypted and stored successfully');
});

retrieveAndDecryptData(password, 1).then((decryptedData) => {
  console.log('Decrypted data:', decryptedData);
});

// Crypto functions
async function getKeyMaterial(password) {
  const encoder = new TextEncoder();
  return window.crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
}

async function getKey(keyMaterial, salt) {
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function openDatabase() {
  // open or create sqlite database with secure_data table
  
}

async function encryptAndStoreData(password, data) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await getKeyMaterial(password);
  const key = await getKey(keyMaterial, salt);
  const { iv, encryptedData } = await encryptData(key, data);

  // Convert to base64 for storage
  const base64Salt = btoa(String.fromCharCode(...salt));
  const base64Iv = btoa(String.fromCharCode(...iv));
  const base64EncryptedData = btoa(String.fromCharCode(...encryptedData));

  // Store in SQLite
  const db = await openDatabase();
  await db.run('INSERT INTO secure_data (salt, iv, data) VALUES (?, ?, ?)', [
    base64Salt,
    base64Iv,
    base64EncryptedData,
  ]);
}

async function retrieveAndDecryptData(password, id) {
  const db = await openDatabase();
  const row = await db.get(
    'SELECT salt, iv, data FROM secure_data WHERE id = ?',
    [id]
  );

  const salt = Uint8Array.from(atob(row.salt), (c) => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(row.iv), (c) => c.charCodeAt(0));
  const encryptedData = Uint8Array.from(atob(row.data), (c) => c.charCodeAt(0));

  const keyMaterial = await getKeyMaterial(password);
  const key = await getKey(keyMaterial, salt);
  return await decryptData(key, iv, encryptedData);
}
