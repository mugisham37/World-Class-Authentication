import { userRepository, UserRepository } from './user.repository';
import { BaseRepository } from './base.repository';
import { TransactionManager } from './base.repository';

// Export repository interfaces
export { BaseRepository, TransactionManager, UserRepository };

// Export repository implementations
export { userRepository };

// Export a repositories object for convenience
export const repositories = {
  user: userRepository,
};
