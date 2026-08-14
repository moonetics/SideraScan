import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter"
});

export const metadata: Metadata = {
  title: "SideraScan",
  description: "Consent-based Roblox scan review dashboard",
  icons: {
    apple: "/apple-icon.png",
    icon: [
      { rel: "icon", url: "/favicon.ico" },
      { rel: "icon", sizes: "192x192", type: "image/png", url: "/icon.png" }
    ]
  }
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.variable}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
