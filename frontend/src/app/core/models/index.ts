
export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  scan_count: number;
}

export interface Target {
  id: string;
  project_id: string;
  domain: string;
  is_oos: boolean;
  added_at: string;
}

export interface Scan {
  id: string;
  project_id: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  tools: string[];
  wordlist: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error: string;
}

export interface ToolInfo {
  name: string;
  category: string;
  description: string;
  parallel_group: string;
  requires_root: boolean;
  available: boolean;
}

export interface ToolResult {
  id: string;
  scan_id: string;
  project_id: string;
  tool: string;
  category: string;
  domain: string;
  data: any[];
  count: number;
  elapsed_s: number;
  created_at: string;
  error: string;
}

export interface ScanProgressEvent {
  tool: string;
  status: 'running' | 'done' | 'error' | 'skipped' | 'start';
  message: string;
  count: number;
  ts: string;
}

export interface StorageConfig {
  azure_enabled: boolean;
  connection_string: string;
  account_name: string;
  account_key: string;
  table_prefix: string;
}
