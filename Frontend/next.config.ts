import path from "node:path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Pin the filesystem root to this app. Without it Turbopack walks up and
  // picks the lockfile in the user's home directory as the workspace root,
  // which prints a warning on every build and can resolve modules from the
  // wrong tree.
  turbopack: {
    root: path.resolve(__dirname),
  },
};

export default nextConfig;
