"use client"

import { useAuthContext } from "@/lib/auth-context"
import { useUserInfo } from "@/lib/api-hooks"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Shield, User, Settings, Package, Ticket, UserPlus, AlertTriangle } from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useEffect } from "react"
import { AddCustomerForm } from "@/components/add-customer-form"
import { PackagesList } from "@/components/packages-list"
import { TicketsList } from "@/components/tickets-list"

export default function DashboardPage() {
  const { user, isAuthenticated, setUser } = useAuthContext()
  const router = useRouter()
  const { data: userInfo } = useUserInfo()

  const isVulnMode = process.env.NEXT_PUBLIC_VULN_MODE === "true"

  useEffect(() => {
    if (!isAuthenticated) {
      router.push("/login")
    }
  }, [isAuthenticated, router])

  useEffect(() => {
    if (userInfo && !user) {
      setUser(userInfo)
    }
  }, [userInfo, user, setUser])

  if (!isAuthenticated) {
    return null
  }

  const displayName = user?.username || userInfo?.username
  const greeting = displayName ? `Hello, ${displayName}!` : "Welcome to your dashboard!"

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Dashboard</h1>
        <p className="text-muted-foreground">{greeting}</p>

        <div className="mt-4">
          <Badge
            variant={isVulnMode ? "destructive" : "default"}
            className={`${
              isVulnMode ? "bg-red-600 hover:bg-red-700 text-white" : "bg-green-600 hover:bg-green-700 text-white"
            }`}
          >
            {isVulnMode ? (
              <>
                <AlertTriangle className="h-3 w-3 mr-1" />
                Vulnerability Mode Active
              </>
            ) : (
              <>
                <Shield className="h-3 w-3 mr-1" />
                Secure Mode Active
              </>
            )}
          </Badge>
        </div>
      </div>

      {/* User Profile Section */}
      {(user || userInfo) && (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <User className="h-5 w-5" />
                Profile Information
              </CardTitle>
              <CardDescription>Your account details</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <p>
                  <strong>Username:</strong> {(user || userInfo)?.username}
                </p>
                <p>
                  <strong>Email:</strong> {(user || userInfo)?.email}
                </p>
                <p>
                  <strong>Role:</strong> {(user || userInfo)?.role}
                </p>
                <p>
                  <strong>Last Login:</strong>{" "}
                  {(user || userInfo)?.last_login
                    ? new Date((user || userInfo)!.last_login!).toLocaleDateString()
                    : "Never"}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Account Settings
              </CardTitle>
              <CardDescription>Manage your account</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                <Link href="/change-password">
                  <Button variant="outline" className="w-full bg-transparent">
                    Change Password
                  </Button>
                </Link>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Security Status
              </CardTitle>
              <CardDescription>Account security information</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2 text-sm">
                <p>
                  <strong>Account Status:</strong> {(user || userInfo)?.account_locked ? "Locked" : "Active"}
                </p>
                <p>
                  <strong>Created:</strong> {new Date((user || userInfo)!.created_at).toLocaleDateString()}
                </p>
                <p>
                  <strong>Last Updated:</strong> {new Date((user || userInfo)!.updated_at).toLocaleDateString()}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="space-y-8">
        {/* Add Customer Section */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <UserPlus className="h-6 w-6 text-blue-500" />
            <h2 className="text-2xl font-semibold">Add Customer</h2>
          </div>
          <AddCustomerForm />
        </section>

        {/* Packages Section */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <Package className="h-6 w-6 text-purple-500" />
            <h2 className="text-2xl font-semibold">Available Packages</h2>
          </div>
          <PackagesList />
        </section>

        {/* Tickets Section */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <Ticket className="h-6 w-6 text-cyan-500" />
            <h2 className="text-2xl font-semibold">Support Tickets</h2>
          </div>
          <TicketsList />
        </section>
      </div>
    </div>
  )
}
