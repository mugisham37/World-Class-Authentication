import { User } from "../../../data/models/user.model";

/**
 * Extended User interface with display name
 * Adds displayName property required for WebAuthn operations
 */
export interface UserWithDisplayName extends User {
  displayName?: string;
}
