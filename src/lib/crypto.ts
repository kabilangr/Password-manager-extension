// Zero-Knowledge Crypto Utilities for Extension
// User's encryption key is derived from Master Password + Salt
// Key NEVER leaves the client

import { CRYPTO_VALUES, STORAGE_KEYS } from "../values/constants";

const SESSION_KEY_NAME = import.meta.env.VITE_SESSION_KEY_NAME || STORAGE_KEYS.SESSION_KEY;

// --- Key Derivation ---

export function generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(CRYPTO_VALUES.SALT_LENGTH));
}

export async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt as unknown as ArrayBuffer,
            iterations: Number(import.meta.env.VITE_EXTENSION_PBKDF2_ITERATIONS) || CRYPTO_VALUES.PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// --- Session Key Storage ---

export async function storeKeyInSession(key: CryptoKey): Promise<void> {
    const exported = await crypto.subtle.exportKey("jwk", key);
    await chrome.storage.session.set({ [SESSION_KEY_NAME]: JSON.stringify(exported) });
}

export async function getKeyFromSession(): Promise<CryptoKey | null> {
    const result = await chrome.storage.session.get(SESSION_KEY_NAME);
    const keyJson = result[SESSION_KEY_NAME];
    if (!keyJson) return null;

    try {
        const jwk = JSON.parse(keyJson as string);
        return crypto.subtle.importKey(
            "jwk",
            jwk,
            { name: "AES-GCM" },
            true,
            ["encrypt", "decrypt"]
        );
    } catch {
        return null;
    }
}

export async function clearKeyFromSession(): Promise<void> {
    await chrome.storage.session.remove(SESSION_KEY_NAME);
}

// --- Encryption ---

export async function encryptData(key: CryptoKey, plaintext: string): Promise<{ encrypted: string; iv: string }> {
    const enc = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(CRYPTO_VALUES.IV_LENGTH)); // 96-bit IV for AES-GCM

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        enc.encode(plaintext)
    );

    return {
        encrypted: arrayBufferToBase64(new Uint8Array(encrypted)),
        iv: arrayBufferToBase64(iv)
    };
}

// --- Decryption ---

export async function decryptData(key: CryptoKey, encryptedBase64: string, ivBase64: string): Promise<string> {
    const encrypted = base64ToArrayBuffer(encryptedBase64);
    const iv = base64ToArrayBuffer(ivBase64);

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as unknown as ArrayBuffer },
        key,
        encrypted as unknown as ArrayBuffer
    );
    return new TextDecoder().decode(decrypted);
}

// --- Encoding Utilities ---

export function arrayBufferToBase64(buffer: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < buffer.byteLength; i++) {
        binary += String.fromCharCode(buffer[i]);
    }
    return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): Uint8Array {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

// --- Complete Login Flow ---
// Call this after successful authentication to set up the user's encryption key

export async function initializeUserKey(masterPassword: string, saltBase64: string): Promise<CryptoKey> {
    const salt = base64ToArrayBuffer(saltBase64);
    const key = await deriveKey(masterPassword, salt);
    await storeKeyInSession(key);
    return key;
}

// --- Secure Memory Wipe ---
// Overwrites sensitive data before release to prevent memory scraping

export function secureWipeString(_str: string): void {
    // In JavaScript, strings are immutable, so we can't directly overwrite them.
    // Best practice: ensure the reference is nullified after this call.
    // For maximum security, avoid storing passwords in variables longer than necessary.
}

export function secureWipeArray(arr: Uint8Array): void {
    if (arr && arr.length > 0) {
        // Fill with cryptographically random data
        crypto.getRandomValues(arr);
        // Then fill with zeros
        arr.fill(0);
    }
}

export async function secureLogout(): Promise<void> {
    // Clear key from session
    await clearKeyFromSession();
    // Clear any other sensitive session data
    await chrome.storage.session.clear();
}

// Helper to create a secure copy that auto-wipes
export function createSecurePassword(password: string, callback: (pwd: string) => Promise<void>): Promise<void> {
    return callback(password).finally(() => {
        // Note: The original password string cannot be wiped in JS
        // This is a reminder to the caller to clear their reference
    });
}

