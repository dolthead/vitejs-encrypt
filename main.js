main();

async function main() {

  const DB_NAME = "SecureDatabase";
  const TABLE_NAME = "secure_data";
  const userPassword = "user-password";
  const sensitiveData = "Sensitive PII data";
  const indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;
    
  let lastId = 0;

  const db = await openDatabase(DB_NAME, TABLE_NAME);

  await encryptAndStoreData(db, TABLE_NAME, userPassword, sensitiveData)
    .then(id => {
      lastId = id;
      console.log("Encrypted data: ", sensitiveData, "ID: ", id);
    }, error => console.error(`Store error: ${error}`))
    .catch(error => console.error(`Store exception: ${error}`));

  await retrieveAndDecryptData(db, TABLE_NAME, userPassword, lastId)
    .then(decryptedData => console.log("Decrypted data:", decryptedData),
      error => console.error(`Retrieve error: ${error}`))
    .catch(error => console.error(`Retrieve exception: ${error}`));

  db.close();

  console.log("Encryption and decryption complete.");


  // Crypto code

  async function encryptAndStoreData(db, tableName, password, data) {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await getKeyMaterial(password);
    const key = await getKey(keyMaterial, salt);
    const { iv, encryptedData } = await encryptData(key, data);
    // Convert to base64 for storage
    const base64Salt = btoa(String.fromCharCode(...salt));
    const base64Iv = btoa(String.fromCharCode(...iv));
    const base64EncryptedData = btoa(String.fromCharCode(...encryptedData));
    return storeData(db, tableName, { salt: base64Salt, iv: base64Iv, data: base64EncryptedData });
  }

  async function retrieveAndDecryptData(db, tableName, password, id) {
    const row = await getData(db, tableName, id);

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

  function openDatabase(dbName, tableName) {
    return new Promise((resolve, reject) => {
        const dbVersion = 1;
        const request = indexedDB.open(dbName, dbVersion);
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(tableName)) {
                db.createObjectStore(tableName, { keyPath: "id", autoIncrement: true });
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

  async function storeData(db, tableName, data) {
    const transaction = db.transaction(tableName, "readwrite");
    const store = transaction.objectStore(tableName);
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

  async function getData(db, tableName, id) {
    const transaction = db.transaction(tableName, "readonly");
    const store = transaction.objectStore(tableName);
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
} // main
