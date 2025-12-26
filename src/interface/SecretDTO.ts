export interface SecretDTO {
    id: string;
    encryptedData: string;
    iv: string;
    name?: string; // Optional cleartext name for UI
}
