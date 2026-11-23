import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  ScanCommand,
  QueryCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import { extractRBACContext, requireRole, ForbiddenError, NotFoundError, ValidationError } from './rbac';

const client = new DynamoDBClient({});
const docClient = DynamoDBDocumentClient.from(client);
const TABLE_NAME = process.env.MAIN_TABLE || 'projects-table';

interface AuditLog {
  pk: string;
  sk: string;
  action: string;
  userId: string;
  timestamp: number;
  details: Record<string, unknown>;
}

async function createAuditLog(
  action: string,
  userId: string,
  details: Record<string, unknown>
): Promise<void> {
  const auditLog: AuditLog = {
    pk: 'AUDIT',
    sk: `${Date.now()}#${randomUUID()}`,
    action,
    userId,
    timestamp: Date.now(),
    details,
  };
  await docClient.send(new PutCommand({ TableName: TABLE_NAME, Item: auditLog }));
}

function errorResponse(statusCode: number, message: string): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify({ error: message }),
    headers: { 'Content-Type': 'application/json' },
  };
}

function successResponse(statusCode: number, data: unknown): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  };
}

// GET /resources - List all resources
async function handleGetResources(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, ['admin', 'operator', 'viewer']);

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'attribute_exists(id) AND #pk <> :pk',
        ExpressionAttributeNames: { '#pk': 'pk' },
        ExpressionAttributeValues: { ':pk': 'AUDIT' },
      })
    );

    return successResponse(200, {
      items: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error in handleGetResources:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/{tableIndex}/bulk - Bulk import
async function handleBulkImport(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, ['admin', 'operator']);

    const body = JSON.parse(event.body || '{}');
    const items = body.items || [];

    if (!Array.isArray(items) || items.length === 0) {
      return errorResponse(400, 'Invalid request: items must be a non-empty array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      ...item,
      id: item.id || randomUUID(),
      createdAt: item.createdAt || now,
      updatedAt: item.updatedAt || now,
      pk: `${tableIndex}#${item.id || randomUUID()}`,
      sk: `${tableIndex}#${now}`,
    }));

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    // Process in batches of 25
    for (let i = 0; i < processedItems.length; i += 25) {
      const batch = processedItems.slice(i, i + 25);
      const requestItems = batch.map((item) => ({
        PutRequest: {
          Item: item,
        },
      }));

      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: requestItems,
            },
          })
        );
        imported += batch.length;
      } catch (batchError) {
        failed += batch.length;
        errors.push(`Batch ${Math.floor(i / 25) + 1} failed: ${String(batchError)}`);
      }
    }

    // Create audit log
    await createAuditLog('BULK_IMPORT', context.userId, {
      tableIndex,
      imported,
      failed,
      totalItems: items.length,
    });

    return successResponse(200, {
      imported,
      failed,
      errors,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    console.error('Error in handleBulkImport:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// GET /api/{tableIndex}/{id} - Get single resource
async function handleGetResource(
  event: APIGatewayProxyEvent,
  tableIndex: string,
  id: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, ['admin', 'operator', 'viewer']);

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: `${tableIndex}#${id}`,
          sk: `${tableIndex}#${id}`,
        },
      })
    );

    if (!result.Item) {
      return errorResponse(404, `Resource not found: ${id}`);
    }

    return successResponse(200, result.Item);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof NotFoundError) {
      return errorResponse(404, error.message);
    }
    console.error('Error in handleGetResource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// POST /api/{tableIndex} - Create resource
async function handleCreateResource(
  event: APIGatewayProxyEvent,
  tableIndex: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, ['admin', 'operator']);

    const body = JSON.parse(event.body || '{}');
    const id = body.id || randomUUID();
    const now = Date.now();

    const item = {
      ...body,
      id,
      pk: `${tableIndex}#${id}`,
      sk: `${tableIndex}#${id}`,
      createdAt: body.createdAt || now,
      updatedAt: now,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog('CREATE', context.userId, {
      tableIndex,
      id,
      item,
    });

    return successResponse(201, item);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    console.error('Error in handleCreateResource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// PUT /api/{tableIndex}/{id} - Update resource
async function handleUpdateResource(
  event: APIGatewayProxyEvent,
  tableIndex: string,
  id: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, ['admin', 'operator']);

    const body = JSON.parse(event.body || '{}');
    const now = Date.now();

    const updateExpressionParts: string[] = [];
    const expressionAttributeNames: Record<string, string> = {};
    const expressionAttributeValues: Record<string, unknown> = {};

    Object.entries(body).forEach(([key, value], index) => {
      if (key !== 'id' && key !== 'pk' && key !== 'sk' && key !== 'createdAt') {
        const attrName = `#attr${index}`;
        const attrValue = `:val${index}`;
        updateExpressionParts.push(`${attrName} = ${attrValue}`);
        expressionAttributeNames[attrName] = key;
        expressionAttributeValues[attrValue] = value;
      }
    });

    updateExpressionParts.push('#updatedAt = :updatedAt');
    expressionAttributeNames['#updatedAt'] = 'updatedAt';
    expressionAttributeValues[':updatedAt'] = now;

    const result = await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: `${tableIndex}#${id}`,
          sk: `${tableIndex}#${id}`,
        },
        UpdateExpression: `SET ${updateExpressionParts.join(', ')}`,
        ExpressionAttributeNames: expressionAttributeNames,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog('UPDATE', context.userId, {
      tableIndex,
      id,
      changes: body,
    });

    return successResponse(200, result.Attributes);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    console.error('Error in handleUpdateResource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// DELETE /api/{tableIndex}/{id} - Delete resource
async function handleDeleteResource(
  event: APIGatewayProxyEvent,
  tableIndex: string,
  id: string
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractRBACContext(event);
    requireRole(context, ['admin', 'operator']);

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: {
          pk: `${tableIndex}#${id}`,
          sk: `${tableIndex}#${id}`,
        },
      })
    );

    await createAuditLog('DELETE', context.userId, {
      tableIndex,
      id,
    });

    return successResponse(204, null);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    console.error('Error in handleDeleteResource:', error);
    return errorResponse(500, 'Internal server error');
  }
}

// Main handler
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const path = event.path || '';
  const method = event.httpMethod || 'GET';

  try {
    // GET /resources
    if (path === '/resources' && method === 'GET') {
      return await handleGetResources(event);
    }

    // POST /api/{tableIndex}/bulk
    const bulkMatch = path.match(/^\/api\/([^/]+)\/bulk$/);
    if (bulkMatch && method === 'POST') {
      return await handleBulkImport(event, bulkMatch[1]);
    }

    // GET /api/{tableIndex}/{id}
    const getMatch = path.match(/^\/api\/([^/]+)\/([^/]+)$/);
    if (getMatch && method === 'GET') {
      return await handleGetResource(event, getMatch[1], getMatch[2]);
    }

    // POST /api/{tableIndex}
    const createMatch = path.match(/^\/api\/([^/]+)$/);
    if (createMatch && method === 'POST') {
      return await handleCreateResource(event, createMatch[1]);
    }

    // PUT /api/{tableIndex}/{id}
    if (getMatch && method === 'PUT') {
      return await handleUpdateResource(event, getMatch[1], getMatch[2]);
    }

    // DELETE /api/{tableIndex}/{id}
    if (getMatch && method === 'DELETE') {
      return await handleDeleteResource(event, getMatch[1], getMatch[2]);
    }

    return errorResponse(404, 'Not found');
  } catch (error) {
    console.error('Unhandled error:', error);
    return errorResponse(500, 'Internal server error');
  }
}