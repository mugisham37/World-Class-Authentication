import { MetricsCollector } from '../../src/data/connections/metrics-collector';

describe('MetricsCollector', () => {
  let collector: MetricsCollector;

  beforeEach(() => {
    // Reset the singleton instance for each test
    // This is a hack for testing purposes
    (MetricsCollector as any).instance = undefined;
    collector = MetricsCollector.getInstance();
  });

  describe('getHistogramStats', () => {
    it('should handle empty histograms', () => {
      const stats = collector.getHistogramStats('empty');
      expect(stats).toEqual({
        min: 0,
        max: 0,
        avg: 0,
        p95: 0,
        p99: 0
      });
    });

    it('should calculate correct statistics for single value', () => {
      collector.observeHistogram('single', 5);
      const stats = collector.getHistogramStats('single');
      expect(stats.min).toBe(5);
      expect(stats.max).toBe(5);
      expect(stats.avg).toBe(5);
      expect(stats.p95).toBe(5);
      expect(stats.p99).toBe(5);
    });

    it('should calculate correct statistics for multiple values', () => {
      const values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      values.forEach(v => collector.observeHistogram('multi', v));
      const stats = collector.getHistogramStats('multi');
      expect(stats.min).toBe(1);
      expect(stats.max).toBe(10);
      expect(stats.avg).toBe(5.5);
      expect(stats.p95).toBe(10);
      expect(stats.p99).toBe(10);
    });

    it('should handle percentiles correctly for larger datasets', () => {
      // Create a dataset with 100 values
      for (let i = 1; i <= 100; i++) {
        collector.observeHistogram('large', i);
      }
      const stats = collector.getHistogramStats('large');
      expect(stats.p95).toBe(95);
      expect(stats.p99).toBe(99);
    });

    it('should handle edge cases for percentiles', () => {
      // Test with just 2 values
      collector.observeHistogram('edge', 1);
      collector.observeHistogram('edge', 10);
      const stats = collector.getHistogramStats('edge');
      // With 2 values, p95 and p99 should both be the max value
      expect(stats.p95).toBe(10);
      expect(stats.p99).toBe(10);
    });
  });
});
