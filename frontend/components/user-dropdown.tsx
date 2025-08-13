"use client"

import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { User, LogOut, KeyRound, Settings } from "lucide-react"
import Link from "next/link"
import { useAuthContext } from "@/lib/auth-context"
import { useRouter } from "next/navigation"

export function UserDropdown() {
  const { user, setUser, setCsrfToken } = useAuthContext()
  const router = useRouter()

  const handleLogout = async () => {
    try {
      // Clear auth context
      setUser(null)
      setCsrfToken(null)

      // Redirect to homepage
      router.push("/")
    } catch (error) {
      console.error("Logout error:", error)
    }
  }

  if (!user) return null

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="border-blue-500/50 text-blue-400 hover:bg-blue-500/10 bg-transparent"
        >
          <User className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-48 bg-gray-900 border-gray-700">
        <div className="px-2 py-1.5 text-sm text-gray-300">
          <div className="font-medium text-white">{user.username}</div>
          <div className="text-xs text-gray-400">{user.email}</div>
        </div>
        <DropdownMenuSeparator className="bg-gray-700" />
        <DropdownMenuItem asChild className="text-gray-300 hover:bg-gray-800 hover:text-white">
          <Link href="/change-password">
            <KeyRound className="h-4 w-4 mr-2" />
            Change Password
          </Link>
        </DropdownMenuItem>
        <DropdownMenuItem asChild className="text-gray-300 hover:bg-gray-800 hover:text-white">
          <Link href="/dashboard">
            <Settings className="h-4 w-4 mr-2" />
            Dashboard
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator className="bg-gray-700" />
        <DropdownMenuItem onClick={handleLogout} className="text-red-400 hover:bg-red-900/20 hover:text-red-300">
          <LogOut className="h-4 w-4 mr-2" />
          Logout
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
