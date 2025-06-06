import { Injectable } from '@tsed/di';
import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { logger } from '../logging/logger';

/**
 * HTTP client for making external API requests
 */
@Injectable()
export class HttpClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      timeout: 10000, // Default timeout of 10 seconds
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor for logging
    this.client.interceptors.request.use(
      config => {
        logger.debug('Making HTTP request', {
          method: config.method?.toUpperCase(),
          url: config.url,
          headers: config.headers,
        });
        return config;
      },
      error => {
        logger.error('HTTP request error', { error });
        return Promise.reject(error);
      }
    );

    // Add response interceptor for logging
    this.client.interceptors.response.use(
      response => {
        logger.debug('Received HTTP response', {
          status: response.status,
          statusText: response.statusText,
          url: response.config.url,
        });
        return response;
      },
      error => {
        logger.error('HTTP response error', {
          error: error.message,
          status: error.response?.status,
          data: error.response?.data,
        });
        return Promise.reject(error);
      }
    );
  }

  /**
   * Make a GET request
   * @param url URL to request
   * @param options Request options
   * @returns Response data
   */
  async get<T>(url: string, options?: RequestOptions): Promise<T> {
    const config = this.createAxiosConfig(options);
    const response = await this.client.get<T>(url, config);
    return response.data;
  }

  /**
   * Make a POST request
   * @param url URL to request
   * @param data Request body
   * @param options Request options
   * @returns Response data
   */
  async post<T>(url: string, data?: any, options?: RequestOptions): Promise<T> {
    const config = this.createAxiosConfig(options);
    const response = await this.client.post<T>(url, data, config);
    return response.data;
  }

  /**
   * Make a PUT request
   * @param url URL to request
   * @param data Request body
   * @param options Request options
   * @returns Response data
   */
  async put<T>(url: string, data?: any, options?: RequestOptions): Promise<T> {
    const config = this.createAxiosConfig(options);
    const response = await this.client.put<T>(url, data, config);
    return response.data;
  }

  /**
   * Make a DELETE request
   * @param url URL to request
   * @param options Request options
   * @returns Response data
   */
  async delete<T>(url: string, options?: RequestOptions): Promise<T> {
    const config = this.createAxiosConfig(options);
    const response = await this.client.delete<T>(url, config);
    return response.data;
  }

  /**
   * Create Axios config from request options
   * @param options Request options
   * @returns Axios request config
   */
  private createAxiosConfig(options?: RequestOptions): AxiosRequestConfig {
    if (!options) {
      return {};
    }

    return {
      headers: options.headers,
      params: options.params,
      timeout: options.timeout,
      responseType: options.responseType,
      withCredentials: options.withCredentials,
    };
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
