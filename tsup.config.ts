import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['secure.ts'],
  format: ['esm', 'cjs'],   // 同时产出 ESM 和 CJS
  dts: true,                 // 生成 .d.ts 类型声明
  splitting: false,
  sourcemap: true,
  clean: true,
  outDir: 'dist',
  // 让 tsup 把 parseuri.js 也一并打包进去，使用者无需关心内部依赖
  bundle: true,
  // 运行时依赖不内联（使用者自己安装）
  external: ['crypto-js', '@noble/ciphers'],
  esbuildOptions(options) {
    // 小程序 / 浏览器环境的 platform 设为 browser，避免注入 Node.js shim
    options.platform = 'browser'
  },
})
