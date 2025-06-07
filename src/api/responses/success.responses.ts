import type { Response } from 'express';

/**
 * Send a success response with status code 200
 * @param res Express response object
 * @param message Success message
 * @param data Optional data to include in the response
 */
export function sendOkResponse(res: Response, message: string, data?: any): void {
  res.status(200).json({
    status: 'success',
    message,
    data,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send a created response with status code 201
 * @param res Express response object
 * @param message Success message
 * @param data Optional data to include in the response
 */
export function sendCreatedResponse(res: Response, message: string, data?: any): void {
  res.status(201).json({
    status: 'success',
    message,
    data,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send a no content response with status code 204
 * @param res Express response object
 */
export function sendNoContentResponse(res: Response): void {
  res.status(204).end();
}

/**
 * Send a paginated response with status code 200
 * @param res Express response object
 * @param message Success message
 * @param data Data to include in the response
 * @param pagination Pagination information
 */
export function sendPaginatedResponse(
  res: Response,
  message: string,
  data: any[],
  pagination: {
    page: number;
    limit: number;
    totalItems: number;
    totalPages: number;
  }
): void {
  res.status(200).json({
    status: 'success',
    message,
    data,
    pagination,
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send a file download response
 * @param res Express response object
 * @param filename Filename for the download
 * @param data File data
 * @param mimetype MIME type of the file
 */
export function sendFileResponse(
  res: Response,
  filename: string,
  data: Buffer,
  mimetype: string
): void {
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', mimetype);
  res.send(data);
}
