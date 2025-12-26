export const CRYPTO_VALUES = {
    PBKDF2_ITERATIONS: 310000,
    SALT_LENGTH: 16,
    IV_LENGTH: 12,
};

export const API_VALUES = {
    TIMEOUT_MS: 10000,
    DEFAULT_BASE_URL: "http://localhost:3000",
};

export const STORAGE_KEYS = {
    SESSION_KEY: 'ciphervault_derived_key',
    LOCK_TIMEOUT: 'ciphervault_lock_timeout',
    THEME: 'ciphervault_theme',
    PIN_HASH: 'ciphervault_pin_hash',
    LAST_ACTIVITY: 'ciphervault_last_activity',
    FAILED_ATTEMPTS: 'ciphervault_failed_attempts',
    LAST_FAILED_TIME: 'ciphervault_last_failed_time',
};

export const SECURITY_VALUES = {
    MAX_FAILED_ATTEMPTS: 5,
    MAX_BACKOFF_SECONDS: 300,
    DEFAULT_LOCK_TIMEOUT_MINS: 5,
    CLIPBOARD_CLEAR_SECONDS: 30,
};

export const UI_VALUES = {
    ERROR_DISPLAY_MS: 5000,
};
