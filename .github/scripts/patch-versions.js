#!/usr/bin/env node
/**
 * Patches version numbers in Meridian project files.
 * Usage: node patch-versions.js <version>
 *
 * Files patched:
 * - Cargo.toml
 * - Cargo.lock
 */

const fs = require('fs');
const path = require('path');

const version = process.argv[2];
if (!version) {
  console.error('Usage: node patch-versions.js <version>');
  process.exit(1);
}

/**
 * Patch Cargo.toml - updates the version field
 */
function patchCargoToml(filePath, version) {
  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
  }
  const content = fs.readFileSync(filePath, 'utf8');
  const updated = content.replace(
    /^version\s*=\s*"[^"]*"/m,
    `version = "${version}"`
  );
  fs.writeFileSync(filePath, updated);
  console.log(`Patched: ${filePath}`);
}

/**
 * Patch Cargo.lock - updates the version for a specific package
 */
function patchCargoLock(filePath, packageName, version) {
  if (!fs.existsSync(filePath)) {
    console.log(`Skipping (not found): ${filePath}`);
    return;
  }
  const content = fs.readFileSync(filePath, 'utf8');
  const pattern = new RegExp(
    `(\\[\\[package\\]\\]\\nname = "${packageName}"\\nversion = ")[^"]*"`,
  );
  const updated = content.replace(pattern, `$1${version}"`);
  fs.writeFileSync(filePath, updated);
  console.log(`Patched: ${filePath} (${packageName} -> ${version})`);
}

// Main execution
const rootDir = path.resolve(__dirname, '../..');

console.log(`Patching files to version ${version}...`);
console.log('');

patchCargoToml(path.join(rootDir, 'Cargo.toml'), version);
patchCargoLock(path.join(rootDir, 'Cargo.lock'), 'meridian-proxy', version);

console.log('');
console.log(`All files patched to version ${version}`);
