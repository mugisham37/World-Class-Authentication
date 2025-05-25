import { logger } from '../../infrastructure/logging/logger';

/**
 * Metrics collector class
 * Collects and reports metrics for monitoring
 */
export class MetricsCollector {
  private static instance: MetricsCollector;
  private counters: Map<string, number>;
  private gauges: Map<string, number>;
  private histograms: Map<string, number[]>;

  /**
   * Private constructor to enforce singleton pattern
   */
  private constructor() {
    this.counters = new Map<string, number>();
    this.gauges = new Map<string, number>();
    this.histograms = new Map<string, number[]>();
  }

  /**
   * Get the singleton instance
   * @returns The singleton instance
   */
  public static getInstance(): MetricsCollector {
    if (!MetricsCollector.instance) {
      MetricsCollector.instance = new MetricsCollector();
    }
    return MetricsCollector.instance;
  }

  /**
   * Increment a counter
   * @param name The counter name
   * @param value The increment value (default: 1)
   */
  public incrementCounter(name: string, value: number = 1): void {
    const currentValue = this.counters.get(name) || 0;
    this.counters.set(name, currentValue + value);
    logger.debug(`Counter ${name} incremented by ${value} to ${currentValue + value}`);
  }

  /**
   * Get a counter value
   * @param name The counter name
   * @returns The counter value
   */
  public getCounter(name: string): number {
    return this.counters.get(name) || 0;
  }

  /**
   * Reset a counter
   * @param name The counter name
   */
  public resetCounter(name: string): void {
    this.counters.set(name, 0);
    logger.debug(`Counter ${name} reset to 0`);
  }

  /**
   * Set a gauge value
   * @param name The gauge name
   * @param value The gauge value
   */
  public setGauge(name: string, value: number): void {
    this.gauges.set(name, value);
    logger.debug(`Gauge ${name} set to ${value}`);
  }

  /**
   * Increment a gauge
   * @param name The gauge name
   * @param value The increment value (default: 1)
   */
  public incrementGauge(name: string, value: number = 1): void {
    const currentValue = this.gauges.get(name) || 0;
    this.gauges.set(name, currentValue + value);
    logger.debug(`Gauge ${name} incremented by ${value} to ${currentValue + value}`);
  }

  /**
   * Decrement a gauge
   * @param name The gauge name
   * @param value The decrement value (default: 1)
   */
  public decrementGauge(name: string, value: number = 1): void {
    const currentValue = this.gauges.get(name) || 0;
    this.gauges.set(name, Math.max(0, currentValue - value));
    logger.debug(`Gauge ${name} decremented by ${value} to ${Math.max(0, currentValue - value)}`);
  }

  /**
   * Get a gauge value
   * @param name The gauge name
   * @returns The gauge value
   */
  public getGauge(name: string): number {
    return this.gauges.get(name) || 0;
  }

  /**
   * Observe a histogram value
   * @param name The histogram name
   * @param value The observed value
   */
  public observeHistogram(name: string, value: number): void {
    const values = this.histograms.get(name) || [];
    values.push(value);
    this.histograms.set(name, values);
    logger.debug(`Histogram ${name} observed value ${value}`);
  }

  /**
   * Get histogram values
   * @param name The histogram name
   * @returns The histogram values
   */
  public getHistogram(name: string): number[] {
    return this.histograms.get(name) || [];
  }

  /**
   * Get histogram statistics
   * @param name The histogram name
   * @returns The histogram statistics
   */
  public getHistogramStats(name: string): {
    min: number;
    max: number;
    avg: number;
    p95: number;
    p99: number;
  } {
    const values = this.histograms.get(name) || [];
    if (values.length === 0) {
      return { min: 0, max: 0, avg: 0, p95: 0, p99: 0 };
    }

    const sortedValues = [...values].sort((a, b) => a - b);
    const min = sortedValues[0];
    const max = sortedValues[sortedValues.length - 1];
    const avg = sortedValues.reduce((sum, val) => sum + val, 0) / sortedValues.length;

    // Handle edge cases for percentiles
    const p95Index = Math.floor(sortedValues.length * 0.95);
    const p99Index = Math.floor(sortedValues.length * 0.99);

    const p95 = p95Index < sortedValues.length ? sortedValues[p95Index] : max;
    const p99 = p99Index < sortedValues.length ? sortedValues[p99Index] : max;

    return { min, max, avg, p95, p99 };
  }

  /**
   * Reset a histogram
   * @param name The histogram name
   */
  public resetHistogram(name: string): void {
    this.histograms.set(name, []);
    logger.debug(`Histogram ${name} reset`);
  }

  /**
   * Get all metrics
   * @returns All metrics
   */
  public getAllMetrics(): {
    counters: Map<string, number>;
    gauges: Map<string, number>;
    histograms: Map<string, number[]>;
  } {
    return {
      counters: this.counters,
      gauges: this.gauges,
      histograms: this.histograms,
    };
  }

  /**
   * Reset all metrics
   */
  public resetAllMetrics(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
    logger.debug('All metrics reset');
  }
}
