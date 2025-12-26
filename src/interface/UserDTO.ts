export interface UserDTO {
    id: string;
    salt: string; // Base64 encoded salt for key derivation
}
