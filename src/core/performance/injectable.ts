/**
 * Injectable decorator for dependency injection
 */
export const Injectable = (): ClassDecorator => {
  return (target: any) => {
    // This is a simplified version of the decorator
    // In a real application, this would be provided by a DI framework
    return target;
  };
};
