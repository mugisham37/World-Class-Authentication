import { Injectable } from '@tsed/di';

/**
 * HTTP client for making external API requests
 */
@Injectable()
export class HttpClient {
  /**
   * Make a GET request
   * @param url URL to request
   * @param options Request options
   * @returns Response data
   */
  async get<T>(url: string, options?: RequestOptions): Promise<T> {
    // Implementation would use fetch, axios, or another HTTP client
    throw new Error('Not implemented');
  }

  /**
   * Make a POST request
   * @param url URL to request
   * @param data Request body
   * @param options Request options
   * @returns Response data
   */
  async post<T>(url: string, data?: any, options?: RequestOptions): Promise<T> {
    // Implementation would use fetch, axios, or another HTTP client
    throw new Error('Not implemented');
  }

  /**
   * Make a PUT request
   * @param url URL to request
   * @param data Request body
   * @param options Request options
   * @returns Response data
   */
  async put<T>(url: string, data?: any, options?: RequestOptions): Promise<T> {
    // Implementation would use fetch, axios, or another HTTP client
    throw new Error('Not implemented');
  }

  /**
   * Make a DELETE request
   * @param url URL to request
   * @param options Request options
   * @returns Response data
   */
  async delete<T>(url: string, options?: RequestOptions): Promise<T> {
    // Implementation would use fetch, axios, or another HTTP client
    throw new Error('Not implemented');
  }
}

/**
 * HTTP request options
 */
export interface RequestOptions {
  headers?: Record<string, string>;
  params?: Record<string, string>;
  timeout?: number;
  responseType?: 'json' | 'text' | 'blob' | 'arraybuffer';
  withCredentials?: boolean;
}
