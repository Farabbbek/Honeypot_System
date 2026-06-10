/** @type {import('next').NextConfig} */
const nextConfig = {
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://159.89.103.231:8000',
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL || 'ws://159.89.103.231:8000',
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://server:8000/api/:path*',
      },
      {
        source: '/ws/:path*',
        destination: 'http://server:8000/ws/:path*',
      },
    ];
  },
};

export default nextConfig;