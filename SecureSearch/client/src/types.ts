export interface User { id: string; name: string; email: string; }
export interface Doc { id: string; name: string; size: number; extension?: string; wordCount: number; createdAt: string; }
export interface SearchResult extends Doc { snippet: string; }
