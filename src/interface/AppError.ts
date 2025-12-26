export type ErrorCode =
    | 'AUTH_INVALID_CREDENTIALS'
    | 'AUTH_UNAUTHORIZED'
    | 'VAULT_NOT_FOUND'
    | 'DB_ERROR'
    | 'VALIDATION_ERROR'
    | 'INTERNAL_ERROR'
    | 'NETWORK_ERROR';

export interface AppError {
    code: ErrorCode;
    message: string;
    details?: unknown;
}

export type ActionResponse<T = unknown> =
    | { success: true; data: T }
    | { success: false; error: AppError };
