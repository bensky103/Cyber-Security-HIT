"use client"

import type React from "react"
import { ThemeProvider } from "@/components/theme-provider"
import { AuthProvider } from "@/lib/auth-context"
import { QueryClientProvider } from "@tanstack/react-query"
import { QueryClient } from "@tanstack/react-query"
import { setupRTL } from "@/lib/i18n"
import { useEffect } from "react"
import { Header } from "@/components/header"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      retry: (failureCount, error: any) => {
        // Don't retry on 4xx errors except 408, 429
        if (error?.response?.status >= 400 && error?.response?.status < 500) {
          if (error.response.status === 408 || error.response.status === 429) {
            return failureCount < 2
          }
          return false
        }
        return failureCount < 3
      },
    },
    mutations: {
      retry: false,
    },
  },
})

function RTLSetup() {
  useEffect(() => {
    setupRTL()
  }, [])
  return null
}

export default function ClientLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange>
        <AuthProvider>
          <RTLSetup />
          <div className="min-h-screen bg-black">
            <Header />
            <main>{children}</main>
          </div>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  )
}
