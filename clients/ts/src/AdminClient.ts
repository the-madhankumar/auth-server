import { ApiResponse, User } from './types';

export interface AdminClientConfig {
  serverUrl: string;
  adminToken: string;
}

/**
 * A dedicated client for performing administrative actions.
 * Requires an admin access token.
 */
export class AdminClient {
  private readonly serverUrl: string;
  private readonly adminToken: string;

  constructor(config: AdminClientConfig) {
    this.serverUrl = config.serverUrl.replace(/\/$/, "");
    this.adminToken = config.adminToken;
  }

  private async fetchApi<T>(path: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    const headers = new Headers(options.headers || {});
    headers.set("Content-Type", "application/json");
    headers.set("Authorization", `Bearer ${this.adminToken}`);

    const response = await fetch(`${this.serverUrl}${path}`, {
      ...options,
      headers,
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error?.message || "An error occurred");
    }
    return data;
  }

  /**
   * List all users. 
   * TODO(Issue #61): The server currently returns a placeholder until Issue #61 is resolved.
   */
  public async listUsers(): Promise<ApiResponse<User[]>> {
    return this.fetchApi<User[]>("/api/admin/users", { method: "GET" });
  }

  /**
   * Lock a user account.
   * @param userId The ID of the user to lock.
   */
  public async lockUser(userId: string): Promise<ApiResponse<{ userID: string }>> {
    return this.fetchApi<{ userID: string }>(`/api/admin/users/${userId}/lock`, { method: "POST" });
  }

  /**
   * Unlock a user account.
   * @param userId The ID of the user to unlock.
   */
  public async unlockUser(userId: string): Promise<ApiResponse<{ userID: string }>> {
    return this.fetchApi<{ userID: string }>(`/api/admin/users/${userId}/unlock`, { method: "POST" });
  }

  /**
   * Delete a user account permanently.
   * @param userId The ID of the user to delete.
   */
  public async deleteUser(userId: string): Promise<ApiResponse<null>> {
    return this.fetchApi<null>(`/api/admin/users/${userId}`, { method: "DELETE" });
  }
}
