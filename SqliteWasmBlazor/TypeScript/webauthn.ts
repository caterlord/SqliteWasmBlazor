/**
 * WebAuthn registration with PRF extension support.
 * Copied from BlazorPRF.Noble.Crypto for later integration (Phase 2a/4).
 * Browser dialog — minimal .NET surface needed.
 */

import { PrfErrorCode, type PrfCredential, type PrfOptions, type PrfResult } from './crypto-types';
import { arrayBufferToBase64 } from './crypto-utils';

/**
 * Check if the current browser and platform support WebAuthn PRF extension.
 * Note: This only checks for basic WebAuthn support. PRF support can only be
 * truly verified during registration, as it depends on the specific authenticator.
 */
export async function checkPrfSupport(): Promise<boolean> {
    if (!window.PublicKeyCredential) {
        return false;
    }
    return true;
}

/**
 * Register a new WebAuthn credential with PRF extension enabled.
 */
export async function registerCredentialWithPrf(
    displayName: string | null,
    options: PrfOptions
): Promise<PrfResult<PrfCredential>> {
    try {
        const userId = crypto.getRandomValues(new Uint8Array(16));
        const effectiveDisplayName = displayName ?? options.rpName;

        const authenticatorAttachment: AuthenticatorAttachment | undefined =
            options.authenticatorAttachment === 'platform' ? 'platform' :
            options.authenticatorAttachment === 'cross-platform' ? 'cross-platform' :
            undefined;

        const authenticatorSelection: AuthenticatorSelectionCriteria = {
            residentKey: 'preferred',
            userVerification: 'preferred'
        };
        if (authenticatorAttachment !== undefined) {
            authenticatorSelection.authenticatorAttachment = authenticatorAttachment;
        }

        const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            rp: {
                name: options.rpName,
                id: options.rpId ?? window.location.hostname
            },
            user: {
                id: userId,
                name: effectiveDisplayName,
                displayName: effectiveDisplayName
            },
            pubKeyCredParams: [
                { alg: -7, type: 'public-key' },
                { alg: -257, type: 'public-key' }
            ],
            authenticatorSelection,
            timeout: options.timeoutMs,
            attestation: 'none',
            extensions: {
                prf: {}
            } as AuthenticationExtensionsClientInputs
        };

        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        }) as PublicKeyCredential | null;

        if (credential === null) {
            return { success: false, cancelled: true };
        }

        const extensionResults = credential.getClientExtensionResults() as {
            prf?: { enabled?: boolean };
        };

        if (!extensionResults.prf?.enabled) {
            return { success: false, errorCode: PrfErrorCode.PrfNotSupported };
        }

        return {
            success: true,
            value: {
                id: credential.id,
                rawId: arrayBufferToBase64(credential.rawId)
            }
        };
    } catch (error) {
        if (error instanceof DOMException && error.name === 'NotAllowedError') {
            return { success: false, cancelled: true };
        }
        return { success: false, errorCode: PrfErrorCode.RegistrationFailed };
    }
}
