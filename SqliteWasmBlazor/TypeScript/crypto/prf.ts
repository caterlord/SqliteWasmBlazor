/**
 * PRF evaluation for deterministic key derivation via WebAuthn.
 * Copied from BlazorPRF.Noble.Crypto for later integration (Phase 2a/4).
 *
 * Flow: WebAuthn PRF → 32-byte seed → storeKeys(keyId, seed, ttl) → all crypto works.
 * In tests, a random seed replaces the PRF output.
 */

import { PrfErrorCode, type PrfOptions, type PrfResult } from './crypto-types';
import { base64ToArrayBuffer, toBase64, zeroFill } from './crypto-utils';

/**
 * Hash a string using SHA-256 via Web Crypto API.
 */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hashBuffer);
}

/**
 * Evaluate the PRF extension with a given salt to derive a deterministic 32-byte output.
 * The PRF output is returned to C# for secure storage in WASM linear memory.
 *
 * IMPORTANT: The PRF output is sensitive and should be handled securely.
 * This function zeros the internal buffers after returning the Base64 result.
 */
export async function evaluatePrf(
    credentialIdBase64: string,
    salt: string,
    options: PrfOptions
): Promise<PrfResult<string>> {
    let prfOutput: Uint8Array | null = null;

    try {
        const encoder = new TextEncoder();
        const saltBytes = encoder.encode(salt);
        const saltHash = await sha256(saltBytes);

        const credentialId = base64ToArrayBuffer(credentialIdBase64);

        const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId: options.rpId ?? window.location.hostname,
            allowCredentials: [
                {
                    id: credentialId,
                    type: 'public-key'
                }
            ],
            timeout: options.timeoutMs,
            userVerification: 'preferred',
            extensions: {
                prf: {
                    eval: {
                        first: saltHash.buffer as ArrayBuffer
                    }
                }
            } as AuthenticationExtensionsClientInputs
        };

        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        }) as PublicKeyCredential | null;

        if (assertion === null) {
            return { success: false, cancelled: true };
        }

        const extensionResults = assertion.getClientExtensionResults() as {
            prf?: { results?: { first?: ArrayBuffer } };
        };

        const prfResults = extensionResults.prf?.results;

        if (!prfResults?.first) {
            return { success: false, errorCode: PrfErrorCode.PrfNotSupported };
        }

        prfOutput = new Uint8Array(prfResults.first);

        if (prfOutput.length !== 32) {
            return { success: false, errorCode: PrfErrorCode.KeyDerivationFailed };
        }

        const resultBase64 = toBase64(prfOutput);

        return { success: true, value: resultBase64 };
    } catch (error) {
        if (error instanceof DOMException && error.name === 'NotAllowedError') {
            return { success: false, cancelled: true };
        }
        return { success: false, errorCode: PrfErrorCode.KeyDerivationFailed };
    } finally {
        if (prfOutput) {
            zeroFill(prfOutput);
        }
    }
}

/**
 * Evaluate PRF without a specific credential ID (discoverable credential).
 * The authenticator will prompt the user to select a credential.
 */
export async function evaluatePrfDiscoverable(
    salt: string,
    options: PrfOptions
): Promise<PrfResult<{ credentialId: string; prfOutput: string }>> {
    let prfOutput: Uint8Array | null = null;

    try {
        const encoder = new TextEncoder();
        const saltBytes = encoder.encode(salt);
        const saltHash = await sha256(saltBytes);

        const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rpId: options.rpId ?? window.location.hostname,
            userVerification: 'preferred',
            extensions: {
                prf: {
                    eval: {
                        first: saltHash.buffer as ArrayBuffer
                    }
                }
            } as AuthenticationExtensionsClientInputs
        };

        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        }) as PublicKeyCredential | null;

        if (assertion === null) {
            return { success: false, cancelled: true };
        }

        const extensionResults = assertion.getClientExtensionResults() as {
            prf?: { results?: { first?: ArrayBuffer } };
        };

        const prfResults = extensionResults.prf?.results;

        if (!prfResults?.first) {
            return { success: false, errorCode: PrfErrorCode.PrfNotSupported };
        }

        prfOutput = new Uint8Array(prfResults.first);

        if (prfOutput.length !== 32) {
            return { success: false, errorCode: PrfErrorCode.KeyDerivationFailed };
        }

        const resultBase64 = toBase64(prfOutput);
        const credentialIdBase64 = toBase64(new Uint8Array(assertion.rawId));

        return {
            success: true,
            value: { credentialId: credentialIdBase64, prfOutput: resultBase64 }
        };
    } catch (error) {
        if (error instanceof DOMException && error.name === 'NotAllowedError') {
            return { success: false, cancelled: true };
        }
        return { success: false, errorCode: PrfErrorCode.KeyDerivationFailed };
    } finally {
        if (prfOutput) {
            zeroFill(prfOutput);
        }
    }
}
