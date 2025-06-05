import { type User, type UserProfile, UserStatus, UserRole } from '../../data/models/user.model';
import { securityConfig } from '../../config/security-config';
import { credentialRepository } from '../../data/repositories/credential.repository';
import { passwordHistoryRepository } from '../../data/repositories/password-history.repository';
import { userProfileRepository } from '../../data/repositories/user-profile.repository';
import { userRepository } from '../../data/repositories/implementations/user.repository.impl';
import { logger } from '../../infrastructure/logging/logger';
import { encryption } from '../../infrastructure/security/crypto/encryption';
import { passwordHasher } from '../../infrastructure/security/crypto/password-hasher';
import { BadRequestError, ConflictError, NotFoundError } from '../../utils/error-handling';
import { emitEvent } from '../events/event-bus';
import { EventType } from '../events/event-types';
import { CredentialType } from '../../data/models/credential.model';

/**
 * User service for SSO integration
 * This service is used by the SAML service for user provisioning and management
 */
export class UserService {
  /**
   * Find a user by email
   * @param email User email
   * @returns User or null if not found
   */
  async findByEmail(email: string): Promise<User | null> {
    return await userRepository.findByEmail(email);
  }

  /**
   * Create a new user
   * @param userData User data
   * @returns Created user
   */
  async create(userData: {
    email: string;
    emailVerified?: boolean;
    firstName?: string | null;
    lastName?: string | null;
    displayName?: string | null;
    username?: string | null;
    groups?: string[];
    roles?: string[];
    [key: string]: any;
  }): Promise<User> {
    // Check if email already exists
    const emailExists = await userRepository.findByEmail(userData.email);
    if (emailExists) {
      throw new ConflictError('Email already in use', 'EMAIL_IN_USE');
    }

    // Check if username already exists
    if (userData.username) {
      const usernameExists = await userRepository.findByUsername(userData.username);
      if (usernameExists) {
        throw new ConflictError('Username already in use', 'USERNAME_IN_USE');
      }
    }

    // Create user
    const user = await userRepository.create({
      email: userData.email,
      username: userData.username || null,
      emailVerified: userData.emailVerified || false,
      status: UserStatus.ACTIVE,
      role: UserRole.USER,
    });

    // Create user profile
    const profileData: Record<string, any> = {};

    if (userData.firstName !== undefined) profileData['firstName'] = userData.firstName;
    if (userData.lastName !== undefined) profileData['lastName'] = userData.lastName;
    if (userData.displayName !== undefined) profileData['displayName'] = userData.displayName;

    if (Object.keys(profileData).length > 0) {
      await userProfileRepository.create({
        userId: user.id,
        ...profileData,
      });
    }

    // Emit user registered event
    emitEvent(EventType.USER_REGISTERED, {
      userId: user.id,
      email: user.email,
      username: user.username,
      timestamp: new Date(),
      source: 'sso',
    });

    logger.info('User created via SSO', { userId: user.id, email: user.email });

    return user;
  }

  /**
   * Update a user
   * @param id User ID
   * @param userData User data to update
   * @returns Updated user
   */
  async update(
    id: string,
    userData: {
      email?: string;
      username?: string | null;
      firstName?: string | null;
      lastName?: string | null;
      displayName?: string | null;
      [key: string]: any;
    }
  ): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(id);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Check if email is being changed and if it's already in use
    if (userData.email && userData.email !== user.email) {
      const emailExists = await userRepository.findByEmail(userData.email);
      if (emailExists && emailExists.id !== id) {
        throw new ConflictError('Email already in use', 'EMAIL_IN_USE');
      }
    }

    // Check if username is being changed and if it's already in use
    if (userData.username && userData.username !== user.username) {
      const usernameExists = await userRepository.findByUsername(userData.username);
      if (usernameExists && usernameExists.id !== id) {
        throw new ConflictError('Username already in use', 'USERNAME_IN_USE');
      }
    }

    // Extract user data and profile data
    const userUpdateData: Record<string, any> = {};
    const profileUpdateData: Record<string, any> = {};

    // User data
    if (userData.email !== undefined) userUpdateData['email'] = userData.email;
    if (userData.username !== undefined) userUpdateData['username'] = userData.username;

    // Profile data
    if (userData.firstName !== undefined) profileUpdateData['firstName'] = userData.firstName;
    if (userData.lastName !== undefined) profileUpdateData['lastName'] = userData.lastName;
    if (userData.displayName !== undefined) profileUpdateData['displayName'] = userData.displayName;

    // Update user if there are user fields to update
    let updatedUser = user;
    if (Object.keys(userUpdateData).length > 0) {
      updatedUser = await userRepository.update(id, userUpdateData);
    }

    // Update profile if there are profile fields to update
    if (Object.keys(profileUpdateData).length > 0) {
      const profile = await userProfileRepository.findByUserId(id);
      if (profile) {
        await userProfileRepository.updateByUserId(id, profileUpdateData);
      } else {
        await userProfileRepository.create({
          userId: id,
          ...profileUpdateData,
        });
      }
    }

    // Emit user updated event
    emitEvent(EventType.USER_UPDATED, {
      userId: updatedUser.id,
      email: updatedUser.email,
      username: updatedUser.username,
      timestamp: new Date(),
      source: 'sso',
    });

    logger.info('User updated via SSO', { userId: updatedUser.id });

    return updatedUser;
  }
}

/**
 * Identity service for managing user identities and profiles
 */
export class IdentityService {
  /**
   * Create a new user
   * @param email User email
   * @param password User password
   * @param username Optional username
   * @param firstName Optional first name
   * @param lastName Optional last name
   * @returns Created user
   */
  async createUser(
    email: string,
    password: string,
    username?: string,
    firstName?: string | null,
    lastName?: string | null
  ): Promise<User> {
    // Check if email already exists
    const emailExists = await userRepository.findByEmail(email);
    if (emailExists) {
      throw new ConflictError('Email already in use', 'EMAIL_IN_USE');
    }

    // Check if username already exists
    if (username) {
      const usernameExists = await userRepository.findByUsername(username);
      if (usernameExists) {
        throw new ConflictError('Username already in use', 'USERNAME_IN_USE');
      }
    }

    // Validate password against policy
    this.validatePasswordAgainstPolicy(password);

    // Create user
    const user = await userRepository.create({
      email,
      username: username || null,
      emailVerified: false,
      status: UserStatus.ACTIVE,
      role: UserRole.USER,
    });

    // Create password credential
    const hashedPassword = await passwordHasher.hash(password);
    const credential = await credentialRepository.create({
      userId: user.id,
      type: CredentialType.PASSWORD,
      identifier: email,
      secret: hashedPassword,
      algorithm: 'argon2id',
    });

    // Add password to history
    await passwordHistoryRepository.create({
      userId: user.id,
      credentialId: credential.id,
      passwordHash: hashedPassword,
    });

    // Create user profile
    if (firstName !== undefined || lastName !== undefined) {
      await userProfileRepository.create({
        userId: user.id,
        firstName: firstName || null,
        lastName: lastName || null,
      });
    }

    // Emit user registered event
    emitEvent(EventType.USER_REGISTERED, {
      userId: user.id,
      email: user.email,
      username: user.username,
      timestamp: new Date(),
    });

    logger.info('User created successfully', { userId: user.id, email: user.email });

    return user;
  }

  /**
   * Get a user by ID
   * @param id User ID
   * @returns User or null if not found
   */
  async getUserById(id: string): Promise<User | null> {
    return await userRepository.findById(id);
  }

  /**
   * Get a user by email
   * @param email User email
   * @returns User or null if not found
   */
  async getUserByEmail(email: string): Promise<User | null> {
    return await userRepository.findByEmail(email);
  }

  /**
   * Get a user by username
   * @param username Username
   * @returns User or null if not found
   */
  async getUserByUsername(username: string): Promise<User | null> {
    return await userRepository.findByUsername(username);
  }

  /**
   * Update a user
   * @param id User ID
   * @param data User data to update
   * @returns Updated user
   */
  async updateUser(
    id: string,
    data: {
      email?: string;
      username?: string | null;
      status?: UserStatus;
    }
  ): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(id);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Check if email is being changed and if it's already in use
    if (data.email && data.email !== user.email) {
      const emailExists = await userRepository.findByEmail(data.email);
      if (emailExists) {
        throw new ConflictError('Email already in use', 'EMAIL_IN_USE');
      }
    }

    // Check if username is being changed and if it's already in use
    if (data.username && data.username !== user.username) {
      const usernameExists = await userRepository.findByUsername(data.username);
      if (usernameExists) {
        throw new ConflictError('Username already in use', 'USERNAME_IN_USE');
      }
    }

    // Update user
    const updatedUser = await userRepository.update(id, data);

    // Emit user updated event
    emitEvent(EventType.USER_UPDATED, {
      userId: updatedUser.id,
      email: updatedUser.email,
      username: updatedUser.username,
      timestamp: new Date(),
    });

    logger.info('User updated successfully', { userId: updatedUser.id });

    return updatedUser;
  }

  /**
   * Delete a user
   * @param id User ID
   * @returns Deleted user
   */
  async deleteUser(id: string): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(id);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Store user data before deletion
    const userData = { ...user };

    // Delete user
    const deleted = await userRepository.delete(id);

    if (!deleted) {
      throw new Error(`Failed to delete user with ID ${id}`);
    }

    // Emit user deleted event
    emitEvent(EventType.USER_DELETED, {
      userId: userData.id,
      email: userData.email,
      username: userData.username,
      timestamp: new Date(),
    });

    logger.info('User deleted successfully', { userId: userData.id });

    return userData;
  }

  /**
   * Change user password
   * @param id User ID
   * @param currentPassword Current password
   * @param newPassword New password
   * @returns Updated user
   */
  async changePassword(id: string, currentPassword: string, newPassword: string): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(id);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Get password credential
    const credentials = await credentialRepository.findByUserIdAndType(id, CredentialType.PASSWORD);
    if (!credentials || credentials.length === 0) {
      throw new NotFoundError('Password credential not found', 'CREDENTIAL_NOT_FOUND');
    }

    // Get the first credential since we expect only one password credential per user
    const passwordCredential = credentials[0];

    if (!passwordCredential) {
      throw new NotFoundError('Password credential not found', 'CREDENTIAL_NOT_FOUND');
    }

    // Verify current password
    const isPasswordValid = await passwordHasher.verify(currentPassword, passwordCredential.secret);
    if (!isPasswordValid) {
      throw new BadRequestError('Current password is incorrect', 'INVALID_PASSWORD');
    }

    // Validate new password against policy
    this.validatePasswordAgainstPolicy(newPassword);

    // Check if new password is different from current password
    if (currentPassword === newPassword) {
      throw new BadRequestError(
        'New password must be different from current password',
        'PASSWORD_REUSE'
      );
    }

    // Check if new password is in password history
    await this.checkPasswordHistory(id, newPassword);

    // Hash new password
    const hashedPassword = await passwordHasher.hash(newPassword);

    // Update password credential
    await credentialRepository.update(passwordCredential.id, {
      secret: hashedPassword,
      lastUsedAt: new Date(),
    });

    // Add new password to history
    await passwordHistoryRepository.create({
      userId: id,
      credentialId: passwordCredential.id,
      passwordHash: hashedPassword,
    });

    // Prune password history if needed
    await this.prunePasswordHistory(id);

    logger.info('User password changed successfully', { userId: id });

    return user;
  }

  /**
   * Reset user password
   * @param id User ID
   * @param newPassword New password
   * @returns Updated user
   */
  async resetPassword(id: string, newPassword: string): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(id);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Validate new password against policy
    this.validatePasswordAgainstPolicy(newPassword);

    // Check if new password is in password history
    await this.checkPasswordHistory(id, newPassword);

    // Get password credential
    const credentials = await credentialRepository.findByUserIdAndType(id, CredentialType.PASSWORD);
    if (!credentials || credentials.length === 0) {
      throw new NotFoundError('Password credential not found', 'CREDENTIAL_NOT_FOUND');
    }

    // Get the first credential
    const passwordCredential = credentials[0];

    if (!passwordCredential) {
      throw new NotFoundError('Password credential not found', 'CREDENTIAL_NOT_FOUND');
    }

    // Hash new password
    const hashedPassword = await passwordHasher.hash(newPassword);

    // Update password credential
    await credentialRepository.update(passwordCredential.id, {
      secret: hashedPassword,
      lastUsedAt: new Date(),
    });

    // Add new password to history
    await passwordHistoryRepository.create({
      userId: id,
      credentialId: passwordCredential.id,
      passwordHash: hashedPassword,
    });

    // Prune password history if needed
    await this.prunePasswordHistory(id);

    logger.info('User password reset successfully', { userId: id });

    return user;
  }

  /**
   * Get user profile
   * @param userId User ID
   * @returns User profile or null if not found
   */
  async getUserProfile(userId: string): Promise<UserProfile | null> {
    // Check if user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    return await userProfileRepository.findByUserId(userId);
  }

  /**
   * Update user profile
   * @param userId User ID
   * @param data Profile data to update
   * @returns Updated user profile
   */
  async updateUserProfile(
    userId: string,
    data: {
      firstName?: string | null;
      lastName?: string | null;
      bio?: string | null;
      avatarUrl?: string | null;
      birthDate?: Date | null;
      phone?: string | null;
      address?: string | null;
      city?: string | null;
      state?: string | null;
      country?: string | null;
      zipCode?: string | null;
    }
  ): Promise<UserProfile> {
    // Check if user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Check if profile exists, create if it doesn't
    const profile = await userProfileRepository.findByUserId(userId);

    if (profile) {
      // Update existing profile
      return await userProfileRepository.updateByUserId(userId, data);
    } else {
      // Create new profile
      return await userProfileRepository.create({
        ...data,
        userId,
      });
    }
  }

  /**
   * Verify user email
   * @param userId User ID
   * @returns Updated user
   */
  async verifyEmail(userId: string): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Update user
    const updatedUser = await userRepository.update(userId, { emailVerified: true });

    logger.info('User email verified successfully', { userId });

    return updatedUser;
  }

  /**
   * Lock user account
   * @param userId User ID
   * @param durationMinutes Lock duration in minutes
   * @returns Updated user
   */
  async lockAccount(userId: string, durationMinutes = 30): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Calculate lock expiration time
    const lockUntil = new Date(Date.now() + durationMinutes * 60 * 1000);

    // Lock account
    const updatedUser = await userRepository.update(userId, { status: UserStatus.LOCKED });

    logger.info('User account locked successfully', { userId, lockUntil });

    return updatedUser;
  }

  /**
   * Unlock user account
   * @param userId User ID
   * @returns Updated user
   */
  async unlockAccount(userId: string): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Unlock account
    const updatedUser = await userRepository.update(userId, { status: UserStatus.ACTIVE });

    logger.info('User account unlocked successfully', { userId });

    return updatedUser;
  }

  /**
   * Increment failed login attempts
   * @param userId User ID
   * @returns Updated user
   */
  async incrementFailedLoginAttempts(userId: string): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Since we don't have failedLoginAttempts in our User model, we'll just return the user
    // In a real implementation, you would update the user's failed login attempts
    return user;
  }

  /**
   * Reset failed login attempts
   * @param userId User ID
   * @returns Updated user
   */
  async resetFailedLoginAttempts(userId: string): Promise<User> {
    // Check if user exists
    const user = await userRepository.findById(userId);
    if (!user) {
      throw new NotFoundError('User not found', 'USER_NOT_FOUND');
    }

    // Since we don't have failedLoginAttempts in our User model, we'll just return the user
    // In a real implementation, you would reset the user's failed login attempts
    return user;
  }

  /**
   * Validate password against policy
   * @param password Password to validate
   * @throws BadRequestError if password doesn't meet policy requirements
   */
  private validatePasswordAgainstPolicy(password: string): void {
    const { minLength, requireLowercase, requireUppercase, requireNumbers, requireSymbols } =
      securityConfig.password;

    // Check minimum length
    if (password.length < minLength) {
      throw new BadRequestError(
        `Password must be at least ${minLength} characters long`,
        'PASSWORD_TOO_SHORT'
      );
    }

    // Check for lowercase letters
    if (requireLowercase && !/[a-z]/.test(password)) {
      throw new BadRequestError(
        'Password must contain at least one lowercase letter',
        'PASSWORD_REQUIRES_LOWERCASE'
      );
    }

    // Check for uppercase letters
    if (requireUppercase && !/[A-Z]/.test(password)) {
      throw new BadRequestError(
        'Password must contain at least one uppercase letter',
        'PASSWORD_REQUIRES_UPPERCASE'
      );
    }

    // Check for numbers
    if (requireNumbers && !/[0-9]/.test(password)) {
      throw new BadRequestError(
        'Password must contain at least one number',
        'PASSWORD_REQUIRES_NUMBER'
      );
    }

    // Check for symbols
    if (requireSymbols && !/[^a-zA-Z0-9]/.test(password)) {
      throw new BadRequestError(
        'Password must contain at least one special character',
        'PASSWORD_REQUIRES_SYMBOL'
      );
    }
  }

  /**
   * Check if password is in password history
   * @param userId User ID
   * @param password Password to check
   * @throws BadRequestError if password is in history
   */
  private async checkPasswordHistory(userId: string, password: string): Promise<void> {
    // Get password history
    const history = await passwordHistoryRepository.findByUserId(userId);

    // Check each password in history
    for (const record of history) {
      const isMatch = await passwordHasher.verify(password, record.passwordHash);
      if (isMatch) {
        throw new BadRequestError(
          'Password has been used recently. Please choose a different password.',
          'PASSWORD_IN_HISTORY'
        );
      }
    }
  }

  /**
   * Prune password history to keep only the most recent entries
   * @param userId User ID
   */
  private async prunePasswordHistory(userId: string): Promise<void> {
    const { maxHistory } = securityConfig.password;

    // Count current history entries
    const count = await passwordHistoryRepository.countByUserId(userId);

    // If we have more than the max, delete the oldest ones
    if (count > maxHistory) {
      // Get all history entries for the user
      const allHistory = await passwordHistoryRepository.findByUserId(userId);

      // Sort by creation date (newest first)
      allHistory.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      // Get the IDs of entries to keep
      const entriesToKeep = allHistory.slice(0, maxHistory);
      const keepIds = new Set(entriesToKeep.map(entry => entry.id));

      // Delete entries that are not in the keep list
      for (const entry of allHistory) {
        if (!keepIds.has(entry.id)) {
          await passwordHistoryRepository.delete(entry.id);
        }
      }

      logger.info(`Deleted old password history records for user ${userId}`, {
        kept: maxHistory,
        deleted: count - maxHistory,
      });
    }
  }

  /**
   * Encrypt sensitive data
   * @param data Data to encrypt
   * @returns Encrypted data
   */
  encryptSensitiveData(data: string): string {
    try {
      const encrypted = encryption.encrypt(data);
      return encrypted; // encrypt always returns string according to our interface
    } catch (error) {
      logger.error('Failed to encrypt sensitive data', { error });
      throw new Error('Encryption failed');
    }
  }

  /**
   * Decrypt sensitive data
   * @param encryptedData Encrypted data
   * @returns Decrypted data
   */
  decryptSensitiveData(encryptedData: string): string {
    try {
      const decrypted = encryption.decrypt(encryptedData);

      // Handle both string and Buffer return types
      if (typeof decrypted === 'string') {
        return decrypted;
      }

      if (Buffer.isBuffer(decrypted)) {
        return decrypted.toString('utf-8');
      }

      throw new Error('Unexpected decryption result type');
    } catch (error) {
      logger.error('Failed to decrypt sensitive data', { error });
      throw new Error('Decryption failed');
    }
  }
}

// Export a singleton instance
export const identityService = new IdentityService();
