import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PLATFORMS = {
  "darwin-arm64": "@jpwesselink/dotsec-core-darwin-arm64",
  "darwin-x64": "@jpwesselink/dotsec-core-darwin-x64",
  "linux-x64": "@jpwesselink/dotsec-core-linux-x64-gnu",
  "linux-arm64": "@jpwesselink/dotsec-core-linux-arm64-gnu",
  "win32-x64": "@jpwesselink/dotsec-core-win32-x64-msvc",
  "win32-arm64": "@jpwesselink/dotsec-core-win32-arm64-msvc",
};

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORMS[key];

if (!pkg) {
  throw new Error(
    `@jpwesselink/dotsec-core: unsupported platform ${process.platform}-${process.arch}\n` +
    `Supported: ${Object.keys(PLATFORMS).join(", ")}`
  );
}

let nativeModule;
try {
  nativeModule = require(pkg);
} catch {
  try {
    const pkgDir = path.dirname(require.resolve(`${pkg}/package.json`));
    nativeModule = require(path.join(pkgDir, "dotsec-core.node"));
  } catch {
    try {
      nativeModule = require(path.join(__dirname, "dotsec-core.node"));
    } catch {
      throw new Error(
        `@jpwesselink/dotsec-core: could not load native module "${pkg}"\n\n` +
        `This usually means the optional dependency was not installed.\n` +
        `Try reinstalling with: npm install @jpwesselink/dotsec-core`
      );
    }
  }
}

export const { parse, validate, toJson, format } = nativeModule;
export default nativeModule;
