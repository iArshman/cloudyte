# Cloudyte API Documentation

This document provides a detailed overview of all the API endpoints available in the backend. 
You can use these endpoints to build a custom Android app, desktop client, or alternative web frontend.

---

## 1. Authentication

Most endpoints require authentication. To authenticate, include the `Authorization` header with a Bearer token or provide a `token` query parameter.

**Header Format:**
```
Authorization: Bearer <your_session_token>
```
*Note: Admin endpoints can also be accessed using Basic Auth if you have the direct admin credentials: `Authorization: Basic <base64(admin:password)>`.*

---

## 2. Public / Auth Endpoints

### Get Public Settings
Returns the public registration settings (e.g., whether registration is enabled).
- **URL:** `GET /api/public/settings`
- **Auth Required:** No
- **Response:**
  ```json
  {
    "registrationEnabled": true,
    "webRegistrationEnabled": true,
    "botRegistrationEnabled": true
  }
  ```

### User Registration
Register a new account.
- **URL:** `POST /api/register`
- **Auth Required:** No
- **Body:** (JSON)
  ```json
  {
    "username": "myuser",
    "password": "mypassword"
  }
  ```
- **Response:** `{ "success": true }`

### User Login
Authenticate and receive a session token.
- **URL:** `POST /api/login`
- **Auth Required:** No
- **Body:** (JSON)
  ```json
  {
    "username": "myuser",
    "password": "mypassword"
  }
  ```
- **Response:**
  ```json
  {
    "success": true,
    "token": "a1b2c3d4...",
    "username": "myuser",
    "isAdmin": false
  }
  ```

### Logout
Invalidate the current session token.
- **URL:** `POST /api/logout`
- **Auth Required:** Yes
- **Response:** `{ "success": true }`

---

## 3. Current User / Accounts

### Get Current User Profile
Retrieves the logged-in user's profile and settings.
- **URL:** `GET /api/me`
- **Auth Required:** Yes
- **Response:**
  ```json
  {
    "authenticated": true,
    "username": "myuser",
    "isAdmin": false,
    "settings": {
      "username": "myuser",
      "backupEnabled": false,
      "backupAccId": null
    }
  }
  ```

### Update User Settings
- **URL:** `POST /api/user/settings`
- **Auth Required:** Yes
- **Body:** (JSON)
  ```json
  {
    "backupEnabled": true,
    "backupAccId": "account_id_here",
    "isDefaultAccId": "account_id_here"
  }
  ```
- **Response:** `{ "success": true }`

### List Linked Accounts (Drives)
List all drives (Telegram, Google Drive, OneDrive) connected to the current user.
- **URL:** `GET /api/accounts`
- **Auth Required:** Yes
- **Query Params:** `userId` (Admin only - filters by user)
- **Response:** Array of account objects with storage usage.
  ```json
  [
    {
      "id": "abc...",
      "name": "My TG Drive",
      "email": "Channel: -10012345678",
      "accountType": "tgdrive",
      "usage": "1.5 GB",
      "total": "∞",
      "percentage": 0,
      "fileCount": 150,
      "isDefault": true
    }
  ]
  ```

### Delete/Unlink Account
- **URL:** `DELETE /api/accounts/:id`
- **Auth Required:** Yes
- **Response:** `{ "success": true }`

### Register Telegram Drive
Links a Telegram channel as a storage drive.
- **URL:** `POST /api/tgdrive/register`
- **Auth Required:** Yes
- **Body:** (JSON)
  ```json
  {
    "channelId": "-10012345678",
    "driveName": "My Movies Drive"
  }
  ```
- **Response:** `{ "success": true, "id": "acc_id", "channelId": "-10012345678", "name": "My Movies Drive" }`

---

## 4. File Operations

### List Files and Folders
Get files for a specific account and folder.
- **URL:** `GET /api/files`
- **Auth Required:** Yes
- **Query Params:**
  - `accountId` (required): ID of the drive/account
  - `folderId` (optional): ID of the folder (use `root` or omit for top level)
  - `search` (optional): Search query string
- **Response:** Array of file/folder objects.

### Create Folder
- **URL:** `POST /api/folders`
- **Auth Required:** Yes
- **Query Params:** `accountId` (required)
- **Body:** (JSON)
  ```json
  {
    "name": "New Folder Name",
    "parentId": "root" // or specific folder ID
  }
  ```
- **Response:** `{ "success": true }`

### Upload File
- **URL:** `POST /api/upload/:accountId`
- **Auth Required:** Yes
- **Body:** (Multipart Form-Data)
  - `file`: The actual file payload
  - `folderId`: The ID of the parent folder (or "root")
- **Response:** `{ "success": true }`

### Download File
- **URL:** `GET /api/download/:accountId/:fileId`
- **Auth Required:** Yes
- **Query Params:**
  - `preview=1` (optional): Sets Content-Disposition to inline (useful for images/videos in-app)
- **Response:** Binary file stream. Supports `Range` headers for video streaming.

### Rename File
- **URL:** `PATCH /api/files/:fileId`
- **Auth Required:** Yes
- **Query Params:** `accountId` (required)
- **Body:** (JSON)
  ```json
  {
    "name": "new_name.mp4"
  }
  ```
- **Response:** `{ "success": true }`

### Delete File
- **URL:** `DELETE /api/files/:fileId`
- **Auth Required:** Yes
- **Query Params:** `accountId` (required)
- **Response:** `{ "success": true }`

### Move File
- **URL:** `POST /api/files/move`
- **Auth Required:** Yes
- **Body:** (JSON)
  ```json
  {
    "sourceAccountId": "acc_id",
    "fileId": "file_id",
    "targetAccountId": "acc_id",
    "targetFolderId": "folder_id"
  }
  ```
- **Response:** `{ "success": true }`

### Copy File
- **URL:** `POST /api/files/copy`
- **Auth Required:** Yes
- **Body:** (JSON)
  ```json
  {
    "sourceAccountId": "acc_id",
    "fileId": "file_id",
    "targetAccountId": "acc_id",
    "targetFolderId": "folder_id"
  }
  ```
- **Response:** `{ "success": true }`

### Share File (Generate Link)
Generates a public URL to view/download a file without auth.
- **URL:** `POST /api/share`
- **Auth Required:** Yes
- **Body:** (JSON)
  ```json
  {
    "accountId": "acc_id",
    "fileId": "file_id"
  }
  ```
- **Response:** `{ "success": true, "shareUrl": "https://.../s/123456" }`

---

## 5. Public Share Links (No Auth Required)

### Download Shared File
- **URL:** `GET /api/public/download/:shareId`
- **Auth Required:** No
- **Response:** Binary file stream.

### View Shared File Webpage
- **URL:** `GET /s/:shareId`
- **Auth Required:** No
- **Response:** HTML page to view/download the file.

---

## 6. Admin Endpoints

All endpoints below require the authenticated user to have `isAdmin: true` (or use the Basic Auth credentials).

### Get Dashboard Stats
- **URL:** `GET /api/admin/stats`
- **Response:** `{ "totalUsers": 10, "totalAccounts": 15, "totalFiles": 100 }`

### List All Users
- **URL:** `GET /api/admin/users`
- **Response:** Array of user objects with account counts.

### Get Single User Details
- **URL:** `GET /api/admin/users/:id`
- **Response:** `{ "user": {...}, "accounts": [...], "stats": { "fileCount": 5 } }`

### Toggle User Active Status
Ban or unban a user.
- **URL:** `POST /api/admin/users/:id/toggle`
- **Response:** `{ "success": true, "isActive": false }`

### Delete User
Permanently deletes the user and all their linked accounts/files.
- **URL:** `DELETE /api/admin/users/:id`
- **Response:** `{ "success": true }`

### Get Global Settings
- **URL:** `GET /api/admin/settings`
- **Response:** `{ "registrationEnabled": true, "webRegistrationEnabled": true, ... }`

### Update Global Setting
- **URL:** `POST /api/admin/settings`
- **Body:** (JSON)
  ```json
  {
    "key": "registrationEnabled",
    "value": false
  }
  ```
- **Response:** `{ "success": true }`

---

## 7. OAuth Flows

*(Note: These are mostly meant for browsers rather than native app integration, but included for completeness)*

- **GET /api/auth/drive-link**: Returns the Google OAuth redirect URL.
- **GET /api/auth/onedrive-link**: Returns the Microsoft OAuth redirect URL.
- **GET /auth/google/callback**: Google OAuth callback.
- **GET /auth/microsoft/callback**: Microsoft OAuth callback.
