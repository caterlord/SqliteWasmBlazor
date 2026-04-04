/**
 * Core type definitions for SqliteWasmBlazor crypto layer.
 */

export interface EncryptedMessage {
    ephemeralPublicKey: string; // Base64
    ciphertext: string;         // Base64
    nonce: string;              // Base64
}

export interface SymmetricEncryptedMessage {
    ciphertext: string; // Base64
    nonce: string;      // Base64
}

export interface KeyCacheConfig {
    strategy: 'none' | 'session' | 'timed';
    ttlMs: number;
}

export enum CryptoErrorCode {
    Unknown = 'Unknown',
    AuthenticationTagMismatch = 'AuthenticationTagMismatch',
    InvalidData = 'InvalidData',
    KeyDerivationFailed = 'KeyDerivationFailed',
    EncryptionFailed = 'EncryptionFailed',
    DecryptionFailed = 'DecryptionFailed',
}

// ============================================================
// WebAuthn PRF Types
// ============================================================

export interface PrfCredential {
    id: string;
    rawId: string; // Base64 encoded
}

export interface PrfOptions {
    rpName: string;
    rpId?: string;
    timeoutMs: number;
    authenticatorAttachment: 'platform' | 'cross-platform' | 'any';
}

export interface PrfResult<T> {
    success: boolean;
    value?: T;
    errorCode?: PrfErrorCode;
    cancelled?: boolean;
}

/**
 * Error codes for PRF operations.
 * Messages are defined in C# to support localization.
 */
export enum PrfErrorCode {
    Unknown = 'Unknown',
    PrfNotSupported = 'PrfNotSupported',
    CredentialNotFound = 'CredentialNotFound',
    AuthenticationTagMismatch = 'AuthenticationTagMismatch',
    InvalidData = 'InvalidData',
    KeyDerivationFailed = 'KeyDerivationFailed',
    EncryptionFailed = 'EncryptionFailed',
    DecryptionFailed = 'DecryptionFailed',
    RegistrationFailed = 'RegistrationFailed',
}

// WebAuthn PRF extension types
export interface PrfExtensionInput {
    eval?: {
        first: ArrayBuffer;
        second?: ArrayBuffer;
    };
    evalByCredential?: Record<string, {
        first: ArrayBuffer;
        second?: ArrayBuffer;
    }>;
}

export interface PrfExtensionOutput {
    enabled?: boolean;
    results?: {
        first: ArrayBuffer;
        second?: ArrayBuffer;
    };
}
