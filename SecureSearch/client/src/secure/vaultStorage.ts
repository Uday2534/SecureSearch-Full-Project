import type { EncryptedEnvelope } from "./crypto";

const DB_NAME = "secure-search-v2";
const STORE_NAME = "vault";
const VAULT_KEY = "client-state";

function openVaultDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("Could not open secure vault storage."));
  });
}

/** Only the encrypted envelope is written to IndexedDB. */
export async function saveEncryptedVault(envelope: EncryptedEnvelope): Promise<void> {
  const db = await openVaultDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(envelope, VAULT_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("Could not save vault."));
      tx.onabort = () => reject(tx.error ?? new Error("Vault save was aborted."));
    });
  } finally {
    db.close();
  }
}

export async function loadEncryptedVault(): Promise<EncryptedEnvelope | null> {
  const db = await openVaultDb();
  try {
    return await new Promise((resolve, reject) => {
      const request = db.transaction(STORE_NAME, "readonly").objectStore(STORE_NAME).get(VAULT_KEY);
      request.onsuccess = () => resolve((request.result as EncryptedEnvelope | undefined) ?? null);
      request.onerror = () => reject(request.error ?? new Error("Could not load vault."));
    });
  } finally {
    db.close();
  }
}

export async function clearEncryptedVault(): Promise<void> {
  const db = await openVaultDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).delete(VAULT_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("Could not clear vault."));
      tx.onabort = () => reject(tx.error ?? new Error("Vault clear was aborted."));
    });
  } finally {
    db.close();
  }
}
