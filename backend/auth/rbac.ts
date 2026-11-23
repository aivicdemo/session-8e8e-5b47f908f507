import { APIGatewayProxyEvent } from 'aws-lambda';

export type Role = 'admin' | 'operator' | 'viewer';

export interface RBACContext {
  userId: string;
  role: Role;
  email?: string;
}

export function extractRBACContext(event: APIGatewayProxyEvent): RBACContext {
  const authHeader = event.headers['Authorization'] || event.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');

  if (!token) {
    throw new Error('Missing authorization token');
  }

  const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString('utf-8'));
  const role = (decoded.role || 'viewer') as Role;
  const userId = decoded.sub || decoded.userId || 'unknown';
  const email = decoded.email;

  return { userId, role, email };
}

export function requireRole(context: RBACContext, allowedRoles: Role[]): void {
  if (!allowedRoles.includes(context.role)) {
    throw new ForbiddenError(`Role ${context.role} is not allowed for this operation`);
  }
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ValidationError';
  }
}