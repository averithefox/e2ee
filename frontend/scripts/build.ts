import tailwind from 'bun-plugin-tailwind';
import path from 'node:path';

const result = await Bun.build({
  entrypoints: ['src/index.html', 'src/sw.ts'],
  define: {
    PUBLIC_KEY: (await Bun.file(path.join(__dirname, '../..', 'public.pem')).text())
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, '')
  },
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
