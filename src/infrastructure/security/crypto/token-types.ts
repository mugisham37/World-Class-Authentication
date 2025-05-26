/**
 * Interface for access token payload
 */
export interface AccessTokenPayload {
  sub: string;
  email: string;
  sessionId: string;
}

/**
 * Interface for refresh token payload
 */
export interface RefreshTokenPayload {
  sub: string;
  sessionId: string;
}
