/** @type {import('next').NextConfig} */
module.exports = {
  async rewrites() {
    // Show the existing site (public/index.html) at the home address.
    return { beforeFiles: [{ source: "/", destination: "/index.html" }] };
  },
  async headers() {
    return [{
      source: "/(.*)",
      headers: [
        { key: "X-Frame-Options", value: "DENY" },
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }
      ]
    }];
  }
};
 
