import path from "node:path";
import { defineConfig } from "@rspress/core";

export default defineConfig({
  root: "docs",
  base: "/dotsec-rs/",
  title: "dotsec",
  description: "Encrypt and manage .env files with AWS KMS envelope encryption",
  globalStyles: path.join(__dirname, "docs/styles/index.css"),
  head: [
    ['script', { src: '/dotsec-rs/version-switcher.js', defer: '' }],
  ],
  themeConfig: {
    socialLinks: [
      { icon: "github", mode: "link", content: "https://github.com/jpwesselink/dotsec-rs" },
    ],
  },
});
