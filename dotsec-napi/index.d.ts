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
}

/** Parse a .env file string and return entries with their directives. */
export declare function parse(source: string): ParsedEntry[];

/** Validate entries from a .env file string. Returns a list of validation errors. */
export declare function validate(source: string): ParsedValidationError[];

/** Convert a .env file string to JSON. */
export declare function toJson(source: string): string;

/** Roundtrip: parse a .env file string and serialize it back. */
export declare function format(source: string): string;
