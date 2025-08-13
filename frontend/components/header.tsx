"use client"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Shield, ShieldAlert, LogIn, UserPlus } from "lucide-react"
import Link from "next/link"
import { useAuthContext } from "@/lib/auth-context"
import { UserDropdown } from "./user-dropdown"

export function Header() {
  const isVulnMode = process.env.NEXT_PUBLIC_VULN_MODE === "true"
  const { isAuthenticated } = useAuthContext()

  return (
    <header className="border-b border-gray-800 bg-black/50 backdrop-blur-sm">
      <div className="container mx-auto px-4 py-3">
        <div className="flex items-center justify-between">
          <Link
            href={isAuthenticated ? "/dashboard" : "/"}
            className="flex items-center gap-3 hover:opacity-80 transition-opacity"
          >
            <Shield className="h-6 w-6 text-blue-400" />
            <h1 className="text-xl font-bold text-white">Communication_LTD</h1>
          </Link>

          <div className="flex items-center gap-4">
            {isAuthenticated ? (
              <UserDropdown />
            ) : (
              <div className="flex items-center gap-2">
                <Button
                  asChild
                  variant="outline"
                  size="sm"
                  className="border-blue-500/50 text-blue-400 hover:bg-blue-500/10 bg-transparent"
                >
                  <Link href="/login">
                    <LogIn className="h-4 w-4 mr-2" />
                    Login
                  </Link>
                </Button>
                <Button asChild size="sm" className="bg-blue-600 hover:bg-blue-700">
                  <Link href="/register">
                    <UserPlus className="h-4 w-4 mr-2" />
                    Register
                  </Link>
                </Button>
              </div>
            )}

            {isVulnMode && (
              <Badge variant="destructive" className="flex items-center gap-1 bg-red-600 hover:bg-red-700">
                <ShieldAlert className="h-3 w-3" />
                VULN MODE
              </Badge>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}
