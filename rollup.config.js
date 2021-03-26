import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import polyfills from 'rollup-plugin-node-polyfills';
import inject from '@rollup/plugin-inject';
import resolve from '@rollup/plugin-node-resolve';

export default {
  input: 'src/index.js',
  output: {
    file: 'src/index.mjs',
    format: 'es',
  },
  plugins: [
    polyfills(),
    json(),
    resolve({
      browser: true,
    }),
    commonjs(),
    inject({
      Buffer: ['buffer-es6', 'Buffer'],
    }),
  ],
  external: [
    'crypto',
    '@asoltys/bitcoin-ops/map',
    'merkle-lib/fastRoot',
    'bip174/src/lib/converter/varint',
    'bip174/src/lib/utils',
    ...Object.keys(require('./package.json').dependencies || {}),
  ],
};
