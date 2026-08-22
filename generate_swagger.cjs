const fs = require('fs');

const swagger = {
  "openapi": "3.0.0",
  "info": {
    "title": "Cloudyte Headless API",
    "version": "1.0.0",
    "description": "Complete A-to-Z control of the Cloudyte platform via REST API."
  },
  "servers": [ { "url": "/", "description": "Current Environment" } ],
  "components": {
    "securitySchemes": {
      "bearerAuth": { "type": "http", "scheme": "bearer", "bearerFormat": "API Key or JWT" }
    }
  },
  "security": [ { "bearerAuth": [] } ],
  "paths": {}
};

function addPath(path, method, summary, tags, options = {}) {
  if (!swagger.paths[path]) swagger.paths[path] = {};
  swagger.paths[path][method] = {
    summary,
    tags,
    responses: { "200": { "description": "Successful response" } },
    ...options
  };
  if (tags.includes('Public')) {
    swagger.paths[path][method].security = [];
  }
}

// ─── AUTH & PUBLIC ────────────────────────────────────────────────────────
addPath('/api/register', 'post', 'Register a new user', ['Auth & Public'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { username: { type: 'string' }, password: { type: 'string' } } } } } }
});
addPath('/api/login', 'post', 'Login to get a JWT token', ['Auth & Public'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { username: { type: 'string' }, password: { type: 'string' } } } } } }
});
addPath('/api/logout', 'post', 'Logout the current session', ['Auth & Public']);
addPath('/api/public/settings', 'get', 'Get public registration settings', ['Auth & Public']);
addPath('/api/public/download/{shareId}', 'get', 'Download a shared file', ['Auth & Public'], {
  parameters: [{ name: 'shareId', in: 'path', required: true, schema: { type: 'string' } }]
});

// ─── USER ─────────────────────────────────────────────────────────────
addPath('/api/me', 'get', 'Get current user profile', ['User']);
addPath('/api/user/settings', 'post', 'Update user settings', ['User'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object' } } } }
});
addPath('/api/user/api-keys', 'get', 'List API keys', ['User']);
addPath('/api/user/api-keys', 'post', 'Generate a new API key', ['User'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string' } } } } } }
});
addPath('/api/user/api-keys/{id}', 'delete', 'Revoke an API key', ['User'], {
  parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }]
});

// ─── ACCOUNTS ──────────────────────────────────────────────────────────
addPath('/api/accounts', 'get', 'List connected accounts', ['Accounts']);
addPath('/api/accounts/{id}', 'delete', 'Remove a connected account', ['Accounts'], {
  parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }]
});
addPath('/api/accounts/google', 'post', 'Attach Google Drive via API', ['Accounts'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { tokens: { type: 'object' }, driveName: { type: 'string' }, email: { type: 'string' } } } } } }
});
addPath('/api/accounts/onedrive', 'post', 'Attach OneDrive via API', ['Accounts'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { tokens: { type: 'object' }, driveName: { type: 'string' }, email: { type: 'string' } } } } } }
});
addPath('/api/tgdrive/register', 'post', 'Register a Telegram channel as a drive', ['Accounts'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { channelId: { type: 'string' }, driveName: { type: 'string' } } } } } }
});

// ─── FILES ────────────────────────────────────────────────────────────
addPath('/api/files', 'get', 'List files and folders', ['Files'], {
  parameters: [
    { name: 'accountId', in: 'query', required: true, schema: { type: 'string' } },
    { name: 'folderId', in: 'query', schema: { type: 'string' } },
    { name: 'search', in: 'query', schema: { type: 'string' } }
  ]
});
addPath('/api/folders', 'post', 'Create a new folder', ['Files'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, name: { type: 'string' }, parentId: { type: 'string' } } } } } }
});
addPath('/api/files/{fileId}', 'patch', 'Rename a file or folder', ['Files'], {
  parameters: [{ name: 'fileId', in: 'path', required: true, schema: { type: 'string' } }],
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, name: { type: 'string' } } } } } }
});
addPath('/api/files/{fileId}', 'delete', 'Delete a file or folder', ['Files'], {
  parameters: [{ name: 'fileId', in: 'path', required: true, schema: { type: 'string' } }],
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' } } } } } }
});
addPath('/api/files/move', 'post', 'Move files', ['Files'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, targetAccountId: { type: 'string' }, fileIds: { type: 'array', items: { type: 'string' } }, targetFolderId: { type: 'string' } } } } } }
});
addPath('/api/files/copy', 'post', 'Copy files', ['Files'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, targetAccountId: { type: 'string' }, fileIds: { type: 'array', items: { type: 'string' } }, targetFolderId: { type: 'string' } } } } } }
});
addPath('/api/upload/{accountId}', 'post', 'Upload a file', ['Files'], {
  parameters: [{ name: 'accountId', in: 'path', required: true, schema: { type: 'string' } }],
  requestBody: { content: { 'multipart/form-data': { schema: { type: 'object', properties: { file: { type: 'string', format: 'binary' }, folderId: { type: 'string' } } } } } }
});
addPath('/api/download/{accountId}/{fileId}', 'get', 'Download a file stream', ['Files'], {
  parameters: [{ name: 'accountId', in: 'path', required: true, schema: { type: 'string' } }, { name: 'fileId', in: 'path', required: true, schema: { type: 'string' } }]
});

// ─── SHARES ───────────────────────────────────────────────────────────
addPath('/api/share', 'post', 'Create a share link', ['Shares'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, fileId: { type: 'string' } } } } } }
});
addPath('/api/shares', 'get', 'List all active shares', ['Shares']);
addPath('/api/shares/{shareId}', 'delete', 'Revoke a share link', ['Shares'], {
  parameters: [{ name: 'shareId', in: 'path', required: true, schema: { type: 'string' } }]
});

// ─── ADMIN ────────────────────────────────────────────────────────────
addPath('/api/admin/stats', 'get', 'Get platform stats', ['Admin']);
addPath('/api/admin/users', 'get', 'List all users', ['Admin']);
addPath('/api/admin/users/{id}', 'get', 'Get user details', ['Admin'], {
  parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }]
});
addPath('/api/admin/users/{id}/toggle', 'post', 'Toggle user active status', ['Admin'], {
  parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }]
});
addPath('/api/admin/users/{id}', 'delete', 'Delete a user', ['Admin'], {
  parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }]
});
addPath('/api/admin/settings', 'get', 'Get admin settings', ['Admin']);
addPath('/api/admin/settings', 'post', 'Update admin settings', ['Admin'], {
  requestBody: { content: { 'application/json': { schema: { type: 'object' } } } }
});

fs.writeFileSync('swagger.json', JSON.stringify(swagger, null, 2));
