import type { Metadata, Viewport } from "next";
import { Chivo, Chivo_Mono, Geist, Geist_Mono } from "next/font/google";
import { Providers } from "@/components/providers";
import { site } from "@/lib/site";
import "./globals.css";

const chivo = Chivo({ variable: "--font-chivo", subsets: ["latin"] });
const chivoMono = Chivo_Mono({ variable: "--font-chivo-mono", subsets: ["latin"] });
// the dashboard's face (globals.css swaps it in while a dashboard is on the page); not preloaded elsewhere
const geist = Geist({ variable: "--font-geist", subsets: ["latin"], preload: false });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"], preload: false });

export const metadata: Metadata = {
  title: { default: site.name, template: `%s · ${site.name}` },
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#121110" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
      className={`${chivo.variable} ${chivoMono.variable} ${geist.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
