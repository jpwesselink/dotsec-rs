export interface DirectiveItem {
  name: string;
  value: string | null;
}

export interface ParsedEntry {
  key: string;
  value: string;
  quoteType: string;
  directives: DirectiveItem[];
}

export interface ParsedValidationError {
  key: string;
  message: string;
  severity: string;
}

export interface ParsedSchemaEntry {
  key: string;
  directives: DirectiveItem[];
}

/** Parse a .env file string and return entries with their directives. */
export declare function parse(source: string): ParsedEntry[];

/** Validate entries from a .env file string. Returns a list of validation errors. */
export declare function validate(source: string): ParsedValidationError[];

/** Convert a .env file string to JSON. */
export declare function toJson(source: string): string;

/** Roundtrip: parse a .env file string and serialize it back. */
export declare function format(source: string): string;

/** Validate a .env file against a schema string. Returns validation errors. */
export declare function validateAgainstSchema(source: string, schemaSource: string): ParsedValidationError[];

/** Format a .env file to match schema key ordering. */
export declare function formatBySchema(source: string, schemaSource: string): string;

/** Discover the schema file path for a given .sec file. Returns null if no schema found. */
export declare function discoverSchema(secFilePath: string, explicitSchema?: string | undefined | null): string | null;

/** Load and parse a schema file from disk. Uses discovery if no path given. Returns null if no schema found. */
export declare function loadSchema(secFilePath?: string | undefined | null, explicitSchema?: string | undefined | null): ParsedSchemaEntry[] | null;

/** Parse a schema file string and return entries with their directives. */
export declare function parseSchema(source: string): ParsedSchemaEntry[];

/** Convert a schema file to JSON Schema (draft-07). */
export declare function schemaToJsonSchema(schemaSource: string): string;

/** Generate TypeScript code from a schema file. */
export declare function schemaToTypescript(schemaSource: string): string;
