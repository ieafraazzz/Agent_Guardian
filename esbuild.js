const esbuild = require('esbuild');
const path = require('path');

const watch = process.argv.includes('--watch');
const minify = process.argv.includes('--minify');

async function main() {
  const extensionCtx = await esbuild.context({
    entryPoints: ['./src/extension.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/extension.js',
    external: ['vscode'],
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const proxyCtx = await esbuild.context({
    entryPoints: ['./src/proxy.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/proxy.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const coreCtx = await esbuild.context({
    entryPoints: ['./src/core/index.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/core.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const semanticWorkerCtx = await esbuild.context({
    entryPoints: ['./src/semantic-worker.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/semantic-worker.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  const securityCtx = await esbuild.context({
    entryPoints: ['./src/security/index.ts'],
    bundle: true,
    platform: 'node',
    outfile: './dist/security.js',
    format: 'cjs',
    sourcemap: true,
    minify: minify,
  });

  if (watch) {
    console.log('Watching for changes...');
    await extensionCtx.watch();
    await proxyCtx.watch();
    await coreCtx.watch();
    await semanticWorkerCtx.watch();
    await securityCtx.watch();
  } else {
    await extensionCtx.rebuild();
    await proxyCtx.rebuild();
    await coreCtx.rebuild();
    await semanticWorkerCtx.rebuild();
    await securityCtx.rebuild();
    await extensionCtx.dispose();
    await proxyCtx.dispose();
    await coreCtx.dispose();
    await semanticWorkerCtx.dispose();
    await securityCtx.dispose();
    console.log('Build completed successfully.');
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
