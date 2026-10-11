import type { NextConfig } from "next";

// GitHub Pages (static) için: `output: "export"` şart.
// - Kullanıcı sitesi (kullanici.github.io) → basePath GEREKMEZ.
// - Proje sitesi (kullanici.github.io/repo) → build'te NEXT_PUBLIC_BASE_PATH=/repo ver.
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

const nextConfig: NextConfig = {
  output: "export",
  basePath: basePath || undefined,
  assetPrefix: basePath || undefined,
  trailingSlash: true,
  images: { unoptimized: true },
  /* GitHub Pages static export PPR/cacheComponents ile çalışmaz → kapalı */
  cacheComponents: false,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
