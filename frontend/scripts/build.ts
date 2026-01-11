import tailwind from 'bun-plugin-tailwind';

const result = await Bun.build({
  entrypoints: ['src/index.html'],
  outdir: '../build/public',
  target: 'browser',
  minify: true,
  env: 'inline',
  sourcemap: 'linked',
  plugins: [tailwind]
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  process.exit(1);
}
