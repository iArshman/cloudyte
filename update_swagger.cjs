const fs = require('fs');

const swagger = {
  openapi: "3.0.0",
  info: {
    title: "Cloudyte Headless API",
    version: "1.0.0",
    description: "Welcome to the Cloudyte Headless API documentation!\n\n## Overview\nThis API provides full A-to-Z control of your file manager, allowing you to build custom frontends, automations, and third-party integrations.\n\n## Authentication\nAll secure endpoints require authentication via a **Developer API Key**.\n1. Generate an API Key in the web interface (Settings -> Developer API Keys).\n2. Click the **Authorize** button here and enter your key (e.g., `sk_live_...`).\n3. For your own apps, pass it in the header: `Authorization: Bearer sk_live_...`\n\n## Core Concepts\n- **Accounts**: External storage drives (Telegram, Google Drive, OneDrive) linked to your Cloudyte platform.\n- **Files**: Unified files living inside specific Accounts.\n- **Shares**: Public links generated to securely share files."
  },
  servers: [{ url: "/", description: "Current Environment" }],
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "API Key",
        description: "Enter your Developer API Key (e.g. sk_live_...)"
      }
    },
    schemas: {
      File: {
        type: "object",
        properties: {
          id: { type: "string", example: "64f1b2c3d..." },
          name: { type: "string", example: "document.pdf" },
          type: { type: "string", example: "pdf" },
          size: { type: "number", example: 1048576 },
          createdAt: { type: "string", format: "date-time" },
          isTgDrive: { type: "boolean" }
        }
      },
      Account: {
        type: "object",
        properties: {
          _id: { type: "string", example: "64f1b2c..." },
          accountType: { type: "string", example: "tgdrive" },
          name: { type: "string", example: "My Telegram Drive" },
          email: { type: "string" }
        }
      },
      SuccessResponse: {
        type: "object",
        properties: {
          success: { type: "boolean", example: true }
        }
      },
      ErrorResponse: {
        type: "object",
        properties: {
          error: { type: "string", example: "Detailed error message" }
        }
      }
    }
  },
  security: [{ bearerAuth: [] }],
  paths: {}
};

function addPath(path, method, summary, description, tags, requestBody, responses, parameters = []) {
  if (!swagger.paths[path]) swagger.paths[path] = {};
  
  const endpoint = {
    summary,
    description,
    tags,
    parameters,
    responses: responses || {
      "200": { description: "Successful response" },
      "400": { description: "Bad Request", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } },
      "401": { description: "Unauthorized" },
      "500": { description: "Server Error", content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } } }
    }
  };

  if (requestBody) {
    endpoint.requestBody = requestBody;
  }

  if (tags.includes('Public')) {
    endpoint.security = [];
  }

  swagger.paths[path][method] = endpoint;
}

// ─── AUTH & PUBLIC ────────────────────────────────────────────────────────
addPath('/api/register', 'post', 'Register a new user', 'Creates a new user account on the platform.', ['Auth & Public'], {
  content: { 'application/json': { schema: { type: 'object', properties: { username: { type: 'string', example: 'johndoe' }, password: { type: 'string', example: 'secret123' } } } } }
}, { "200": { description: "Registration successful" } });

addPath('/api/login', 'post', 'Login to get a JWT token', 'Authenticates a user and returns a session token. Not required if using an API Key.', ['Auth & Public'], {
  content: { 'application/json': { schema: { type: 'object', properties: { username: { type: 'string' }, password: { type: 'string' } } } } }
}, { "200": { description: "Login successful with token" } });

// ─── USER ─────────────────────────────────────────────────────────────
addPath('/api/me', 'get', 'Get current user profile', 'Retrieves the details of the currently authenticated user.', ['User'], null, {
  "200": { description: "User profile data" }
});
addPath('/api/user/api-keys', 'get', 'List API keys', 'Returns a list of all active Developer API Keys for the user.', ['User'], null, {
  "200": { description: "List of API keys" }
});
addPath('/api/user/api-keys', 'post', 'Generate a new API key', 'Creates a new Developer API Key for programmatic access.', ['User'], {
  content: { 'application/json': { schema: { type: 'object', properties: { name: { type: 'string', example: "My Custom App" } } } } }
}, { "200": { description: "Returns the newly generated API Key (only visible once)" } });

// ─── ACCOUNTS ──────────────────────────────────────────────────────────
addPath('/api/accounts', 'get', 'List connected accounts', 'Retrieves all storage accounts (Google, OneDrive, Telegram) connected to this user.', ['Accounts'], null, {
  "200": { description: "Array of connected accounts", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/Account" } } } } }
});
addPath('/api/tgdrive/register', 'post', 'Register a Telegram channel as a drive', 'Connects a Telegram channel using the bot integration to act as a limitless file drive.', ['Accounts'], {
  content: { 'application/json': { schema: { type: 'object', properties: { channelId: { type: 'string', example: "-100123456789" }, driveName: { type: 'string', example: "Movies Drive" } } } } }
});

// ─── FILES ────────────────────────────────────────────────────────────
addPath('/api/files', 'get', 'List files and folders', 'Retrieves files and folders within a specific account and optional folder.', ['Files'], null, {
  "200": { description: "Array of files", content: { "application/json": { schema: { type: "array", items: { $ref: "#/components/schemas/File" } } } } }
}, [
  { name: 'accountId', in: 'query', required: true, description: "The ID of the storage account", schema: { type: 'string' } },
  { name: 'folderId', in: 'query', description: "The ID of the parent folder (omit for root)", schema: { type: 'string' } },
  { name: 'search', in: 'query', description: "Optional search term to filter files by name", schema: { type: 'string' } }
]);

addPath('/api/folders', 'post', 'Create a new folder', 'Creates a new directory inside the specified account and parent folder.', ['Files'], {
  content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, name: { type: 'string', example: "New Folder" }, parentId: { type: 'string', description: "ID of the parent folder or 'root'" } } } } }
});

addPath('/api/upload/{accountId}', 'post', 'Upload a file', 'Uploads a file to the specified account. Supports multipart/form-data. For large files, chunking logic is handled internally for OneDrive and Telegram.', ['Files'], {
  content: { 'multipart/form-data': { schema: { type: 'object', properties: { file: { type: 'string', format: 'binary', description: "The file to upload" }, folderId: { type: 'string', description: "Target folder ID (optional)" } } } } }
}, { "200": { description: "File uploaded successfully" } }, [
  { name: 'accountId', in: 'path', required: true, description: "The ID of the storage account", schema: { type: 'string' } }
]);

addPath('/api/download/{accountId}/{fileId}', 'get', 'Download a file stream', 'Returns the raw binary stream of the file. You can pipe this directly to the filesystem or a video player.', ['Files'], null, {
  "200": { description: "Binary file stream", content: { "application/octet-stream": { schema: { type: "string", format: "binary" } } } }
}, [
  { name: 'accountId', in: 'path', required: true, schema: { type: 'string' } },
  { name: 'fileId', in: 'path', required: true, schema: { type: 'string' } }
]);

addPath('/api/files/move', 'post', 'Move files', 'Moves one or more files to a different folder within the same account.', ['Files'], {
  content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, fileIds: { type: 'array', items: { type: 'string' } }, targetFolderId: { type: 'string' } } } } }
});

addPath('/api/files/{fileId}', 'delete', 'Delete a file or folder', 'Permanently removes a file or folder from the storage account.', ['Files'], {
  content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' } } } } }
}, null, [
  { name: 'fileId', in: 'path', required: true, schema: { type: 'string' } }
]);

// ─── SHARES ───────────────────────────────────────────────────────────
addPath('/api/share', 'post', 'Create a share link', 'Generates a public URL to share a file securely with anyone.', ['Shares'], {
  content: { 'application/json': { schema: { type: 'object', properties: { accountId: { type: 'string' }, fileId: { type: 'string' } } } } }
}, {
  "200": { description: "Share link generated", content: { "application/json": { schema: { type: 'object', properties: { success: { type: 'boolean' }, shareUrl: { type: 'string', example: "https://.../s/AbCdEf" } } } } } }
});

addPath('/api/shares', 'get', 'List all active shares', 'Returns all active public share links you have created.', ['Shares']);

addPath('/api/shares/{shareId}', 'delete', 'Revoke a share link', 'Instantly revokes a share link, preventing public access.', ['Shares'], null, null, [
  { name: 'shareId', in: 'path', required: true, description: "The ID of the share (from the end of the URL)", schema: { type: 'string' } }
]);

fs.writeFileSync('swagger.json', JSON.stringify(swagger, null, 2));
console.log("Updated swagger.json with detailed documentation.");
