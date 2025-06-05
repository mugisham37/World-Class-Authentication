/**
 * Event emitter interface for publishing events
 */
export interface EventEmitter {
  /**
   * Emit an event
   * @param eventName Event name
   * @param payload Event payload
   */
  emit(eventName: string, payload: any): void;

  /**
   * Subscribe to an event
   * @param eventName Event name
   * @param handler Event handler
   * @returns Subscription ID
   */
  on(eventName: string, handler: (payload: any) => void): string;

  /**
   * Unsubscribe from an event
   * @param subscriptionId Subscription ID
   */
  off(subscriptionId: string): void;

  /**
   * Subscribe to an event once
   * @param eventName Event name
   * @param handler Event handler
   * @returns Subscription ID
   */
  once(eventName: string, handler: (payload: any) => void): string;
}
