import { WebAuthnService } from '../../src/core/mfa/factors/webauthn.service';
import { WebAuthnErrorType } from '../../src/core/mfa/factors/webauthn.types';
import { MfaFactorType } from '../../src/core/mfa/mfa-factor-types';
import { logger } from '../../src/infrastructure/logging/logger';
import * as simpleWebAuthn from '@simplewebauthn/server';

// Mock dependencies
jest.mock('../../src/infrastructure/logging/logger', () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

jest.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: jest.fn(),
  verifyRegistrationResponse: jest.fn(),
  generateAuthenticationOptions: jest.fn(),
  verifyAuthenticationResponse: jest.fn(),
}));

describe('WebAuthnService', () => {
  let webAuthnService: WebAuthnService;
  let mockMfaFactorRepository: any;
  let mockMfaChallengeRepository: any;
  let mockUserRepository: any;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock repositories
    mockMfaFactorRepository = {
      findById: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    };

    mockMfaChallengeRepository = {
      findById: jest.fn(),
    };

    mockUserRepository = {
      findById: jest.fn(),
    };

    // Create service instance with mocked dependencies
    webAuthnService = new WebAuthnService(
      mockMfaFactorRepository,
      mockMfaChallengeRepository,
      mockUserRepository
    );
  });

  describe('verifyChallenge', () => {
    const challengeId = 'challenge-123';
    const factorId = 'factor-456';
    const userId = 'user-789';
    const credentialId = 'credential-abc';
    const credentialPublicKeyBase64 = 'AAAA';
    const expectedCounter = 5;

    const mockChallenge = {
      id: challengeId,
      factorId,
      challenge: 'challenge-string',
      metadata: {},
    };

    const mockFactor = {
      id: factorId,
      userId,
      type: MfaFactorType.WEBAUTHN,
      credentialId,
      metadata: {
        credentialPublicKey: credentialPublicKeyBase64,
        counter: expectedCounter,
        origin: 'https://example.com',
        rpID: 'example.com',
      },
    };

    const mockAssertionResponse = {
      id: credentialId,
      rawId: credentialId,
      response: {
        clientDataJSON: 'client-data',
        authenticatorData: 'auth-data',
        signature: 'signature',
        userHandle: userId,
      },
      type: 'public-key',
    };

    it('should successfully verify with valid counter increment', async () => {
      // Setup mocks
      mockMfaChallengeRepository.findById.mockResolvedValue(mockChallenge);
      mockMfaFactorRepository.findById.mockResolvedValue(mockFactor);

      // Mock successful verification with incremented counter
      const mockVerification = {
        verified: true,
        authenticationInfo: {
          newCounter: expectedCounter + 1,
        },
      };
      (simpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue(
        mockVerification
      );

      // Call the method
      const result = await webAuthnService.verifyChallenge(
        challengeId,
        mockAssertionResponse as any
      );

      // Assertions
      expect(result.success).toBe(true);
      expect(result.factorId).toBe(factorId);
      expect(result.factorType).toBe(MfaFactorType.WEBAUTHN);

      // Verify counter was updated
      expect(mockMfaFactorRepository.update).toHaveBeenCalledWith(factorId, {
        metadata: {
          ...mockFactor.metadata,
          counter: expectedCounter + 1,
        },
      });
    });

    it('should detect replay attacks by checking counter', async () => {
      // Setup mocks
      mockMfaChallengeRepository.findById.mockResolvedValue(mockChallenge);
      mockMfaFactorRepository.findById.mockResolvedValue(mockFactor);

      // Mock successful verification but with same counter (potential replay attack)
      const mockVerification = {
        verified: true,
        authenticationInfo: {
          newCounter: expectedCounter, // Same as expected counter
        },
      };
      (simpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue(
        mockVerification
      );

      // Call the method
      const result = await webAuthnService.verifyChallenge(
        challengeId,
        mockAssertionResponse as any
      );

      // Assertions
      expect(result.success).toBe(false);
      expect(result.message).toContain('Invalid counter value');

      // Verify warning was logged
      expect(logger.warn).toHaveBeenCalledWith(
        'Possible replay attack detected',
        expect.objectContaining({
          factorId,
          expectedCounter,
          receivedCounter: expectedCounter,
          type: WebAuthnErrorType.REPLAY_ATTACK,
        })
      );

      // Verify counter was NOT updated
      expect(mockMfaFactorRepository.update).not.toHaveBeenCalled();
    });

    it('should handle invalid challenge', async () => {
      // Setup mocks - challenge not found
      mockMfaChallengeRepository.findById.mockResolvedValue(null);

      // Call the method
      const result = await webAuthnService.verifyChallenge(
        challengeId,
        mockAssertionResponse as any
      );

      // Assertions
      expect(result.success).toBe(false);
      expect(logger.warn).toHaveBeenCalledWith(
        'WebAuthn verification failed',
        expect.objectContaining({
          details: expect.objectContaining({
            type: WebAuthnErrorType.INVALID_CHALLENGE,
          }),
        })
      );
    });

    it('should handle invalid factor', async () => {
      // Setup mocks - challenge found but factor not found
      mockMfaChallengeRepository.findById.mockResolvedValue(mockChallenge);
      mockMfaFactorRepository.findById.mockResolvedValue(null);

      // Call the method
      const result = await webAuthnService.verifyChallenge(
        challengeId,
        mockAssertionResponse as any
      );

      // Assertions
      expect(result.success).toBe(false);
      expect(logger.warn).toHaveBeenCalledWith(
        'WebAuthn verification failed',
        expect.objectContaining({
          details: expect.objectContaining({
            type: WebAuthnErrorType.INVALID_FACTOR,
          }),
        })
      );
    });

    it('should handle verification failure', async () => {
      // Setup mocks
      mockMfaChallengeRepository.findById.mockResolvedValue(mockChallenge);
      mockMfaFactorRepository.findById.mockResolvedValue(mockFactor);

      // Mock failed verification
      const mockVerification = {
        verified: false,
      };
      (simpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockResolvedValue(
        mockVerification
      );

      // Call the method
      const result = await webAuthnService.verifyChallenge(
        challengeId,
        mockAssertionResponse as any
      );

      // Assertions
      expect(result.success).toBe(false);
      expect(result.message).toBe('WebAuthn authentication failed');

      // Verify counter was NOT updated
      expect(mockMfaFactorRepository.update).not.toHaveBeenCalled();
    });

    it('should handle unexpected errors', async () => {
      // Setup mocks
      mockMfaChallengeRepository.findById.mockResolvedValue(mockChallenge);
      mockMfaFactorRepository.findById.mockResolvedValue(mockFactor);

      // Mock error during verification
      const error = new Error('Unexpected error');
      (simpleWebAuthn.verifyAuthenticationResponse as jest.Mock).mockRejectedValue(error);

      // Call the method
      const result = await webAuthnService.verifyChallenge(
        challengeId,
        mockAssertionResponse as any
      );

      // Assertions
      expect(result.success).toBe(false);
      expect(result.message).toContain('Unexpected error');

      // Verify error was logged
      expect(logger.error).toHaveBeenCalledWith(
        'Failed to verify WebAuthn challenge',
        expect.objectContaining({
          error,
          challengeId,
        })
      );
    });
  });
});
