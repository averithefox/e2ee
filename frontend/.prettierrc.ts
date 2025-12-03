import { type Config } from 'prettier';

const config: Config = {
  arrowParens: 'avoid',
  bracketSameLine: false,
  bracketSpacing: true,
  printWidth: 120,
  semi: true,
  singleQuote: true,
  tabWidth: 2,
  trailingComma: 'none',
  useTabs: false,
  plugins: ['prettier-plugin-organize-imports', 'prettier-plugin-tailwindcss']
};

export default config;
