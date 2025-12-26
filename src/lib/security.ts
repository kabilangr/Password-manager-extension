// Extension Security Utilities

import { STORAGE_KEYS, SECURITY_VALUES } from "../values/constants";

const PIN_KEY = STORAGE_KEYS.PIN_HASH;
const LOCK_TIMEOUT_KEY = STORAGE_KEYS.LOCK_TIMEOUT;
const LAST_ACTIVITY_KEY = STORAGE_KEYS.LAST_ACTIVITY;
const FAILED_ATTEMPTS_KEY = STORAGE_KEYS.FAILED_ATTEMPTS;
const LAST_FAILED_TIME_KEY = STORAGE_KEYS.LAST_FAILED_TIME;
const MAX_FAILED_ATTEMPTS = Number(import.meta.env.VITE_MAX_FAILED_ATTEMPTS) || SECURITY_VALUES.MAX_FAILED_ATTEMPTS;
const MAX_BACKOFF_SECONDS = Number(import.meta.env.VITE_MAX_BACKOFF_SECONDS) || SECURITY_VALUES.MAX_BACKOFF_SECONDS;

// --- Exponential Backoff ---

export async function getBackoffDelay(): Promise<number> {
    const attempts = await chrome.storage.local.get(FAILED_ATTEMPTS_KEY);
    const currentAttempts = (attempts[FAILED_ATTEMPTS_KEY] as number) || 0;
    if (currentAttempts === 0) return 0;

    // Exponential backoff: 2^attempts seconds, max 5 min
    const delaySeconds = Math.min(Math.pow(2, currentAttempts), MAX_BACKOFF_SECONDS);
    return delaySeconds * 1000; // Return in milliseconds
}

export async function isBackoffActive(): Promise<{ active: boolean; remainingMs: number }> {
    const [attempts, lastFailed] = await Promise.all([
        chrome.storage.local.get(FAILED_ATTEMPTS_KEY),
        chrome.storage.local.get(LAST_FAILED_TIME_KEY)
    ]);

    const currentAttempts = (attempts[FAILED_ATTEMPTS_KEY] as number) || 0;
    const lastFailedTime = (lastFailed[LAST_FAILED_TIME_KEY] as number) || 0;

    if (currentAttempts === 0) return { active: false, remainingMs: 0 };

    const delayMs = Math.min(Math.pow(2, currentAttempts), MAX_BACKOFF_SECONDS) * 1000;
    const unlockTime = lastFailedTime + delayMs;
    const now = Date.now();

    if (now < unlockTime) {
        return { active: true, remainingMs: unlockTime - now };
    }
    return { active: false, remainingMs: 0 };
}

// --- PIN Lock ---

export async function hashPin(pin: string): Promise<string> {
    const encoder = new TextEncoder();
    const pinSalt = import.meta.env.VITE_EXTENSION_PIN_SALT || 'ciphervault_salt';
    const data = encoder.encode(pin + pinSalt);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function setPin(pin: string): Promise<void> {
    const hash = await hashPin(pin);
    await chrome.storage.local.set({ [PIN_KEY]: hash });
}

export async function verifyPin(pin: string): Promise<boolean> {
    const stored = await chrome.storage.local.get(PIN_KEY);
    const hash = await hashPin(pin);

    if (stored[PIN_KEY] === hash) {
        await chrome.storage.local.set({ [FAILED_ATTEMPTS_KEY]: 0 });
        await updateLastActivity();
        return true;
    }

    // Increment failed attempts and record time
    const attempts = await chrome.storage.local.get(FAILED_ATTEMPTS_KEY);
    const currentAttempts = (attempts[FAILED_ATTEMPTS_KEY] as number) || 0;
    const newAttempts = currentAttempts + 1;
    await chrome.storage.local.set({
        [FAILED_ATTEMPTS_KEY]: newAttempts,
        [LAST_FAILED_TIME_KEY]: Date.now()
    });

    // Clear data after max attempts
    if (newAttempts >= MAX_FAILED_ATTEMPTS) {
        await clearSecurityData();
    }

    return false;
}

export async function hasPin(): Promise<boolean> {
    const stored = await chrome.storage.local.get(PIN_KEY);
    return !!stored[PIN_KEY];
}

export async function removePin(): Promise<void> {
    await chrome.storage.local.remove(PIN_KEY);
}

// --- Auto-Lock Timer ---

export async function setLockTimeout(minutes: number): Promise<void> {
    await chrome.storage.local.set({ [LOCK_TIMEOUT_KEY]: minutes });
}

export async function getLockTimeout(): Promise<number> {
    const result = await chrome.storage.local.get(LOCK_TIMEOUT_KEY);
    return (result[LOCK_TIMEOUT_KEY] as number) || SECURITY_VALUES.DEFAULT_LOCK_TIMEOUT_MINS; // Default 5 min
}

export async function updateLastActivity(): Promise<void> {
    await chrome.storage.session.set({ [LAST_ACTIVITY_KEY]: Date.now() });
}

export async function isSessionExpired(): Promise<boolean> {
    const [activity, timeout] = await Promise.all([
        chrome.storage.session.get(LAST_ACTIVITY_KEY),
        getLockTimeout()
    ]);

    const lastActivity = (activity[LAST_ACTIVITY_KEY] as number) || 0;
    const expiresAt = lastActivity + (timeout * 60 * 1000);

    return Date.now() > expiresAt;
}

// --- Secure Clipboard ---

export function copyToClipboard(text: string, clearAfterSeconds: number = SECURITY_VALUES.CLIPBOARD_CLEAR_SECONDS): void {
    navigator.clipboard.writeText(text);

    // Schedule clearing
    setTimeout(async () => {
        // Only clear if still contains our copied value
        try {
            const current = await navigator.clipboard.readText();
            if (current === text) {
                await navigator.clipboard.writeText('');
            }
        } catch {
            // Clipboard read may fail due to permissions
        }
    }, clearAfterSeconds * 1000);
}

// --- Phishing Detection ---

export function extractDomain(url: string): string {
    try {
        const parsed = new URL(url);
        return parsed.hostname.toLowerCase();
    } catch {
        return '';
    }
}

export function checkDomainMatch(currentUrl: string, storedUrl: string): { isMatch: boolean; warning?: string } {
    const currentDomain = extractDomain(currentUrl);
    const storedDomain = extractDomain(storedUrl);

    if (!currentDomain || !storedDomain) {
        return { isMatch: false, warning: 'Invalid URL' };
    }

    if (currentDomain === storedDomain) {
        return { isMatch: true };
    }

    // Check for typosquatting (simple levenshtein distance)
    const distance = levenshteinDistance(currentDomain, storedDomain);
    if (distance <= 2 && distance > 0) {
        return {
            isMatch: false,
            warning: `⚠️ Possible phishing! Domain "${currentDomain}" looks similar to stored "${storedDomain}"`
        };
    }

    return { isMatch: false, warning: 'Domain mismatch' };
}

function levenshteinDistance(a: string, b: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }

    return matrix[b.length][a.length];
}

// --- Clear All Security Data ---

export async function clearSecurityData(): Promise<void> {
    await chrome.storage.local.remove([PIN_KEY, FAILED_ATTEMPTS_KEY]);
    await chrome.storage.session.clear();
}
