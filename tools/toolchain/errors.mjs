/** Stable toolchain failure. `code` is the machine contract; `detail` is bounded operator context. */
export class ToolchainError extends Error {
  /**
   * @param {string} code
   * @param {string} [detail]
   */
  constructor(code, detail) {
    super(detail === undefined ? code : `${code}: ${detail}`);
    this.name = 'ToolchainError';
    this.code = code;
    this.detail = detail;
  }
}

/**
 * @param {string} code
 * @param {string} [detail]
 * @returns {never}
 */
export function fail(code, detail) {
  throw new ToolchainError(code, detail);
}
