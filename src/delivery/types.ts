/**
 * Credential-free Git object and current-pull shapes shared by the authenticated read adapter,
 * trigger resolver, snapshot acquisition, and lifecycle evaluator. These types intentionally
 * contain only normalized data that may cross the delivery trust boundary.
 */
export interface CurrentPull {
  number: number;
  repositoryId: number;
  state: 'open' | 'closed';
  draft: boolean;
  merged: boolean;
  base: { repositoryId: number; ref: string; sha: string };
  head: { repositoryId: number; sha: string };
}

export interface GitCommit {
  sha: string;
  treeSha: string;
}

export interface GitTree {
  sha: string;
  entries: readonly GitTreeEntry[];
  truncated?: boolean;
}

export interface GitTreeEntry {
  path: string;
  mode: string;
  type: 'blob' | 'tree' | 'commit';
  sha: string;
  size?: number | null;
}

export interface GitBlob {
  sha: string;
  encoding: 'base64';
  content: string;
  size: number;
}
