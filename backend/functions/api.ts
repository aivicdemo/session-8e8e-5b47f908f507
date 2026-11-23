import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  BatchWriteItemCommandInput,
} from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  ScanCommand,
  QueryCommand,
  QueryCommandInput,
  ScanCommandInput,
} from '@aws-sdk/lib-dynamodb';
import { v4 as uuidv4 } from 'uuid';
import {
  extractAuthContext,
  requireRole,
  ForbiddenError,
  NotFoundError,
  ValidationError,
} from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
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

interface Resource {
  id: string;
  name: string;
  description?: string;
  createdAt: number;
  updatedAt: number;
  [key: string]: unknown;
}

function createAuditLog(
  action: string,
  userId: string,
  details: Record<string, unknown>
): AuditLog {
  return {
    pk: 'AUDIT',
    sk: `${Date.now()}#${uuidv4()}`,
    action,
    userId,
    timestamp: Date.now(),
    details,
  };
}

async function logAudit(auditLog: AuditLog): Promise<void> {
  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: auditLog,
    })
  );
}

function errorResponse(statusCode: number, message: string): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify({ error: message }),
    headers: { 'Content-Type': 'application/json' },
  };
}

function successResponse(
  statusCode: number,
  data: Record<string, unknown>
): APIGatewayProxyResult {
  return {
    statusCode,
    body: JSON.stringify(data),
    headers: { 'Content-Type': 'application/json' },
  };
}

async function handleGetResources(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requireRole(context, ['admin', 'operator', 'viewer']);

    const params: ScanCommandInput = {
      TableName: TABLE_NAME,
      FilterExpression: 'attribute_not_exists(pk) OR pk <> :auditPk',
      ExpressionAttributeValues: {
        ':auditPk': 'AUDIT',
      },
    };

    const result = await docClient.send(new ScanCommand(params));
    const items = (result.Items || []) as Resource[];

    return successResponse(200, {
      items,
      count: items.length,
    });
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}

async function handleGetResourceById(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requireRole(context, ['admin', 'operator', 'viewer']);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Resource not found');
    }

    return successResponse(200, result.Item as Record<string, unknown>);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof NotFoundError) {
      return errorResponse(404, error.message);
    }
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}

async function handleCreateResource(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requireRole(context, ['admin', 'operator']);

    const body = event.body ? JSON.parse(event.body) : {};

    if (!body.name) {
      return errorResponse(400, 'Missing required field: name');
    }

    const now = Date.now();
    const resource: Resource = {
      id: uuidv4(),
      name: body.name,
      description: body.description,
      createdAt: now,
      updatedAt: now,
      ...body,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: resource,
      })
    );

    const auditLog = createAuditLog('CREATE', context.userId, {
      resourceId: resource.id,
      resourceName: resource.name,
    });
    await logAudit(auditLog);

    return successResponse(201, resource);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof ValidationError) {
      return errorResponse(400, error.message);
    }
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}

async function handleUpdateResource(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requireRole(context, ['admin', 'operator']);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const body = event.body ? JSON.parse(event.body) : {};

    const existingResult = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!existingResult.Item) {
      return errorResponse(404, 'Resource not found');
    }

    const now = Date.now();
    const updateExpression = Object.keys(body)
      .map((key, index) => `${key} = :val${index}`)
      .join(', ');
    const expressionAttributeValues: Record<string, unknown> = {};
    Object.values(body).forEach((value, index) => {
      expressionAttributeValues[`:val${index}`] = value;
    });
    expressionAttributeValues[':updatedAt'] = now;

    await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { id },
        UpdateExpression: `SET ${updateExpression}, updatedAt = :updatedAt`,
        ExpressionAttributeValues: expressionAttributeValues,
      })
    );

    const auditLog = createAuditLog('UPDATE', context.userId, {
      resourceId: id,
      changes: body,
    });
    await logAudit(auditLog);

    const updatedResult = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    return successResponse(200, updatedResult.Item as Record<string, unknown>);
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof NotFoundError) {
      return errorResponse(404, error.message);
    }
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}

async function handleDeleteResource(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requireRole(context, ['admin']);

    const id = event.pathParameters?.id;
    if (!id) {
      return errorResponse(400, 'Missing resource ID');
    }

    const existingResult = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    if (!existingResult.Item) {
      return errorResponse(404, 'Resource not found');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: { id },
      })
    );

    const auditLog = createAuditLog('DELETE', context.userId, {
      resourceId: id,
    });
    await logAudit(auditLog);

    return successResponse(204, {});
  } catch (error) {
    if (error instanceof ForbiddenError) {
      return errorResponse(403, error.message);
    }
    if (error instanceof NotFoundError) {
      return errorResponse(404, error.message);
    }
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}

async function handleBulkImport(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  try {
    const context = extractAuthContext(event);
    requireRole(context, ['admin', 'operator']);

    const body = event.body ? JSON.parse(event.body) : {};
    const items = body.items || [];

    if (!Array.isArray(items) || items.length === 0) {
      return errorResponse(400, 'Invalid or empty items array');
    }

    const now = Date.now();
    const processedItems = items.map((item: Record<string, unknown>) => ({
      ...item,
      id: item.id || uuidv4(),
      createdAt: item.createdAt || now,
      updatedAt: item.updatedAt || now,
    }));

    const chunks: Record<string, unknown>[][] = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    let failed = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const writeRequests = chunk.map((item) => ({
        PutRequest: {
          Item: {
            id: { S: String(item.id) },
            ...Object.entries(item).reduce(
              (acc, [key, value]) => {
                if (key !== 'id') {
                  if (typeof value === 'string') {
                    acc[key] = { S: value };
                  } else if (typeof value === 'number') {
                    acc[key] = { N: String(value) };
                  } else if (typeof value === 'boolean') {
                    acc[key] = { BOOL: value };
                  } else if (value === null) {
                    acc[key] = { NULL: true };
                  } else {
                    acc[key] = { S: JSON.stringify(value) };
                  }
                }
                return acc;
              },
              {} as Record<string, unknown>
            ),
          },
        },
      }));

      const batchParams: BatchWriteItemCommandInput = {
        RequestItems: {
          [TABLE_NAME]: writeRequests,
        },
      };

      try {
        const result = await client.send(new BatchWriteItemCommand(batchParams));
        imported += chunk.length - (result.UnprocessedItems?.[TABLE_NAME]?.length || 0);
        if (result.UnprocessedItems?.[TABLE_NAME]) {
          failed += result.UnprocessedItems[TABLE_NAME].length;
          errors.push(
            `Batch write failed for ${result.UnprocessedItems[TABLE_NAME].length} items`
          );
        }
      } catch (error) {
        failed += chunk.length;
        errors.push(
          `Batch write error: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      }
    }

    const auditLog = createAuditLog('BULK_IMPORT', context.userId, {
      imported,
      failed,
      totalItems: items.length,
    });
    await logAudit(auditLog);

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
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}

export async function handler(
  event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> {
  const httpMethod = event.httpMethod;
  const path = event.path;

  try {
    if (path === '/resources' && httpMethod === 'GET') {
      return await handleGetResources(event);
    }

    if (path.match(/^\/resources\/[^/]+$/) && httpMethod === 'GET') {
      return await handleGetResourceById(event);
    }

    if (path === '/resources' && httpMethod === 'POST') {
      return await handleCreateResource(event);
    }

    if (path.match(/^\/resources\/[^/]+$/) && httpMethod === 'PUT') {
      return await handleUpdateResource(event);
    }

    if (path.match(/^\/resources\/[^/]+$/) && httpMethod === 'DELETE') {
      return await handleDeleteResource(event);
    }

    if (path.match(/^\/api\/\d+\/bulk$/) && httpMethod === 'POST') {
      return await handleBulkImport(event);
    }

    return errorResponse(404, 'Endpoint not found');
  } catch (error) {
    if (error instanceof Error) {
      return errorResponse(500, error.message);
    }
    return errorResponse(500, 'Internal server error');
  }
}