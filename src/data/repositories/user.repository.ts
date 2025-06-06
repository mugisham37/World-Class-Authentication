import { Injectable } from '@tsed/di';
import { User, UserProfile, UserStatus, UserRole } from '../models/user.model';
import { Session } from '../models/session.model';
import * as crypto from 'crypto';

/**
 * Repository for user data
 */
export interface UserRepository {
  /**
   * Find user by ID
   * @param id User ID
   */
  findById(id: string): Promise<User | null>;

  /**
   * Find user by email
   * @param email User email
   */
  findByEmail(email: string): Promise<User | null>;

  /**
   * Reset user password
   * @param userId User ID
   * @param newPassword New password (should be hashed before saving)
   */
  resetPassword(userId: string, newPassword: string): Promise<void>;

  /**
   * Find user by phone number
   * @param phone User phone number
   */
  findByPhone(phone: string): Promise<User | null>;

  /**
   * Find user by username
   * @param username Username
   */
  findByUsername(username: string): Promise<User | null>;

  /**
   * Create a new user
   * @param data User data
   */
  create(data: Partial<User>): Promise<User>;

  /**
   * Update user data
   * @param id User ID
   * @param data User data to update
   */
  update(id: string, data: Partial<User>): Promise<User>;

  /**
   * Delete a user
   * @param id User ID
   * @returns True if the user was deleted, false otherwise
   */
  delete(id: string): Promise<boolean>;

  /**
   * Increment failed login attempts
   * @param id User ID
   * @returns The updated user
   */
  incrementFailedLoginAttempts(id: string): Promise<User>;

  /**
   * Reset failed login attempts
   * @param id User ID
   * @returns The updated user
   */
  resetFailedLoginAttempts(id: string): Promise<User>;

  /**
   * Update last login time
   * @param id User ID
   * @returns The updated user
   */
  updateLastLogin(id: string): Promise<User>;

  /**
   * Find user profile by user ID
   * @param userId User ID
   */
  findProfileByUserId(userId: string): Promise<UserProfile | null>;

  /**
   * Find user sessions by user ID
   * @param userId User ID
   */
  findSessionsByUserId(userId: string): Promise<Session[]>;

  /**
   * Find user preferences by user ID
   * @param userId User ID
   */
  findPreferencesByUserId(userId: string): Promise<any | null>;

  /**
   * Anonymize user profile
   * @param userId User ID
   */
  anonymizeProfile(userId: string): Promise<void>;

  /**
   * Anonymize user sessions
   * @param userId User ID
   */
  anonymizeSessions(userId: string): Promise<void>;
}

/**
 * Implementation of the UserRepository interface
 */
@Injectable()
export class UserRepositoryImpl implements UserRepository {
  // In-memory storage for demo/testing purposes
  private users: Map<string, User> = new Map();
  private profiles: Map<string, UserProfile> = new Map();
  private sessions: Map<string, Session[]> = new Map();
  private preferences: Map<string, any> = new Map();

  async findById(_id: string): Promise<User | null> {
    return this.users.get(_id) || null;
  }

  async findByEmail(_email: string): Promise<User | null> {
    return Array.from(this.users.values()).find(user => user.email === _email) || null;
  }

  async findByPhone(_phone: string): Promise<User | null> {
    return Array.from(this.users.values()).find(user => user.phoneNumber === _phone) || null;
  }

  async findByUsername(_username: string): Promise<User | null> {
    return Array.from(this.users.values()).find(user => user.username === _username) || null;
  }

  async create(_data: Partial<User>): Promise<User> {
    const id = crypto.randomUUID();
    const user: User = {
      id,
      ..._data,
      email: _data.email || '',
      username: _data.username || null,
      password: _data.password || '',
      status: _data.status || UserStatus.PENDING,
      role: _data.role || UserRole.USER,
      active: _data.active !== undefined ? _data.active : true,
      lockedUntil: _data.lockedUntil || null,
      failedLoginAttempts: _data.failedLoginAttempts || 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    } as User;

    this.users.set(id, user);
    return user;
  }

  async update(_id: string, _data: Partial<User>): Promise<User> {
    const user = await this.findById(_id);
    if (!user) throw new Error('User not found');

    const updated = {
      ...user,
      ..._data,
      updatedAt: new Date(),
    };
    this.users.set(_id, updated);
    return updated;
  }

  async delete(_id: string): Promise<boolean> {
    return this.users.delete(_id);
  }

  async incrementFailedLoginAttempts(_id: string): Promise<User> {
    const user = await this.findById(_id);
    if (!user) throw new Error('User not found');

    const updated = {
      ...user,
      failedLoginAttempts: (user.failedLoginAttempts || 0) + 1,
      updatedAt: new Date(),
    };
    this.users.set(_id, updated);
    return updated;
  }

  async resetFailedLoginAttempts(_id: string): Promise<User> {
    const user = await this.findById(_id);
    if (!user) throw new Error('User not found');

    const updated = {
      ...user,
      failedLoginAttempts: 0,
      updatedAt: new Date(),
    };
    this.users.set(_id, updated);
    return updated;
  }

  async updateLastLogin(_id: string): Promise<User> {
    const user = await this.findById(_id);
    if (!user) throw new Error('User not found');

    const updated = {
      ...user,
      lastLoginAt: new Date(),
      updatedAt: new Date(),
    };
    this.users.set(_id, updated);
    return updated;
  }

  async findProfileByUserId(_userId: string): Promise<UserProfile | null> {
    return this.profiles.get(_userId) || null;
  }

  async findSessionsByUserId(_userId: string): Promise<Session[]> {
    return this.sessions.get(_userId) || [];
  }

  async findPreferencesByUserId(_userId: string): Promise<any | null> {
    return this.preferences.get(_userId) || null;
  }

  async anonymizeProfile(_userId: string): Promise<void> {
    const profile = await this.findProfileByUserId(_userId);
    if (!profile) return;

    const anonymized: UserProfile = {
      ...profile,
      firstName: null,
      lastName: null,
      phone: null,
      address: null,
      city: null,
      state: null,
      country: null,
      zipCode: null,
      birthDate: null,
      bio: null,
      avatarUrl: null,
      metadata: null,
      updatedAt: new Date(),
    };

    this.profiles.set(_userId, anonymized);
  }

  async anonymizeSessions(_userId: string): Promise<void> {
    const sessions = await this.findSessionsByUserId(_userId);
    if (!sessions.length) return;

    const anonymizedSessions = sessions.map(session => ({
      ...session,
      ipAddress: null,
      userAgent: null,
      location: null,
      updatedAt: new Date(),
    }));

    this.sessions.set(_userId, anonymizedSessions);
  }

  /**
   * Reset user password
   * @param _userId User ID
   * @param _newPassword New password (should be hashed before saving)
   */
  async resetPassword(_userId: string, _newPassword: string): Promise<void> {
    // Implementation
    // Note: Ensure password is properly hashed before calling this method
    await this.update(_userId, {
      password: _newPassword,
      lastPasswordChange: new Date(),
    });
  }
}

// Export a singleton instance
export const userRepository = new UserRepositoryImpl();
