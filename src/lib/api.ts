const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:3000";

import type { SecretDTO } from "../interface/SecretDTO";
import type { UserDTO } from "../interface/UserDTO";
import type { ActionResponse, AppError } from "../interface/AppError";

/**
 * Enhanced fetch wrapper with timeout and robust error parsing
 */
async function apiFetch(endpoint: string, options: RequestInit = {}) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), 10000); // 10s timeout

    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            signal: controller.signal,
        });
        clearTimeout(id);

        const contentType = response.headers.get("content-type");
        const isJson = contentType && contentType.includes("application/json");
        const data = isJson ? await response.json() : null;

        if (!response.ok) {
            const appError = data?.error;
            const errorMsg = appError?.message || data?.message || `Request failed with status ${response.status}`;
            const error = new Error(errorMsg);
            // @ts-expect-error - Custom property on Error
            if (appError?.code) error.code = appError.code;
            throw error;
        }

        return data;
    } catch (error: unknown) {
        clearTimeout(id);
        if (error instanceof Error && error.name === 'AbortError') {
            throw new Error("Request timed out. Please check your connection.");
        }
        throw error;
    }
}


// Helper to convert unknown error to AppError
function toAppError(e: unknown, code: any = 'INTERNAL_ERROR'): AppError {
    if (e instanceof Error) {
        return {
            code: (e as any).code || code,
            message: e.message
        };
    }
    return {
        code,
        message: String(e)
    };
}

// Fetch user profile including salt for key derivation
export async function fetchUserProfile(): Promise<UserDTO | null> {
    try {
        const data = await apiFetch("/api/auth/get-session", { credentials: "include" });
        if (!data?.user) return null;

        return {
            id: data.user.id,
            salt: data.user.salt || ''
        };
    } catch (e) {
        console.error("Profile fetch failed:", e);
        return null;
    }
}

export async function fetchSecrets(domain?: string): Promise<SecretDTO[]> {
    let url = `/api/autofill`;
    if (domain) url += `?domain=${encodeURIComponent(domain)}`;

    const data = await apiFetch(url, { credentials: "include" });
    // Autofill API now returns structured { success, data: { secrets } }
    return data.data?.secrets || [];
}

export async function login(email: string, password: string): Promise<ActionResponse<{ salt: string }>> {
    try {
        await apiFetch("/api/auth/sign-in/email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ email, password }),
        });

        // After successful login, fetch user profile to get salt
        const profile = await fetchUserProfile();
        if (!profile?.salt) {
            return {
                success: false,
                error: { code: 'AUTH_INVALID_CREDENTIALS', message: "Authentication succeeded but encryption salt is missing. Please contact support." }
            };
        }

        return { success: true, data: { salt: profile.salt } };
    } catch (e: unknown) {
        return { success: false, error: toAppError(e, 'AUTH_INVALID_CREDENTIALS') };
    }
}

// Create a new secret (encrypt client-side before calling)
export async function createSecret(encryptedData: string, iv: string, vaultId: string): Promise<ActionResponse<{ id: string }>> {
    try {
        const res = await apiFetch("/api/secrets", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ encryptedData, iv, vaultId }),
        });
        return { success: true, data: { id: res.data.id } };
    } catch (e: unknown) {
        return { success: false, error: toAppError(e, 'INTERNAL_ERROR') };
    }
}
