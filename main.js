// main code to run

const DB_NAME = "SecureDatabase";
const TABLE_NAME = "secure_data";
const password = "user-password";
const data = "Sensitive PII data";

const indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;

encryptAndStoreData("user-password", "Sensitive PII data")
  .then(id => console.log("Data encrypted and stored successfully with ID:", id), 
    error => console.error(`Store error: ${error}`))
  .catch((error) => console.error(`Store exception: ${error}`));

retrieveAndDecryptData("user-password", 1)
  .then(decryptedData => console.log("Decrypted data:", decryptedData),
    error => console.error(`Retrieve error: ${error}`))
  .catch((error) => console.error(`Retrieve exception: ${error}`));


// Crypto code

async function encryptAndStoreData(password, data) {
  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await getKeyMaterial(password);
  const key = await getKey(keyMaterial, salt);
  const { iv, encryptedData } = await encryptData(key, data);
  // Convert to base64 for storage
  const base64Salt = btoa(String.fromCharCode(...salt));
  const base64Iv = btoa(String.fromCharCode(...iv));
  const base64EncryptedData = btoa(String.fromCharCode(...encryptedData));
  return storeData({ salt: base64Salt, iv: base64Iv, data: base64EncryptedData });
}

async function retrieveAndDecryptData(password, id) {
  const row = await getData(id);

  const salt = Uint8Array.from(atob(row.salt), c => c.charCodeAt(0));
  const iv = Uint8Array.from(atob(row.iv), c => c.charCodeAt(0));
  const encryptedData = Uint8Array.from(atob(row.data), c => c.charCodeAt(0));

  const keyMaterial = await getKeyMaterial(password);
  const key = await getKey(keyMaterial, salt);
  return await decryptData(key, iv, encryptedData);
}

async function encryptData(key, data) {
  const encodedData = new TextEncoder().encode(data);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await window.crypto.subtle.encrypt(
      {
          name: "AES-GCM",
          iv: iv // Initialization vector
      },
      key,
      encodedData
  );
  return {
      iv: iv,
      encryptedData: new Uint8Array(encryptedData)
  };
}

async function decryptData(key, iv, encryptedData) {
  const decryptedData = await window.crypto.subtle.decrypt(
      {
          name: "AES-GCM",
          iv: iv // Initialization vector
      },
      key,
      encryptedData
  );
  return new TextDecoder().decode(decryptedData);
}

async function getKeyMaterial(password) {
  const encoder = new TextEncoder();
  return window.crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
}

async function getKey(keyMaterial, salt) {
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}


// Database code

function openDatabase() {
  return new Promise((resolve, reject) => {
      const dbVersion = 1;
      const request = indexedDB.open(DB_NAME, dbVersion);
      request.onupgradeneeded = (event) => {
          const db = event.target.result;
          if (!db.objectStoreNames.contains(TABLE_NAME)) {
              db.createObjectStore(TABLE_NAME, { keyPath: "id", autoIncrement: true });
          }
      };
      request.onsuccess = (event) => {
          const db = event.target.result;
          resolve(db);
      };
      request.onerror = (event) => {
          reject(`Error opening database: ${event.target.errorCode}`);
      };
  });
}

async function storeData(data) {
  const db = await openDatabase();
  const transaction = db.transaction(TABLE_NAME, "readwrite");
  const store = transaction.objectStore(TABLE_NAME);
  const request = store.add(data);
  return new Promise((resolve, reject) => {
      request.onsuccess = () => {
          resolve(request.result); // Return the ID of the new record
      };
      request.onerror = (event) => {
          reject(`Error storing data: ${event.target.errorCode}`);
      };
  });
}

async function getData(id) {
  const db = await openDatabase();
  const transaction = db.transaction(TABLE_NAME, "readonly");
  const store = transaction.objectStore(TABLE_NAME);
  const request = store.get(id);
  return new Promise((resolve, reject) => {
      request.onsuccess = async (event) => {
          const row = event.target.result;
          if (!row) {
              reject("No data found for the given ID");
              return;
          }
          resolve(row);
      };
      request.onerror = (event) => {
          reject(`Error retrieving data: ${event.target.errorCode}`);
      };
  });
}
