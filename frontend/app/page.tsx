"use client"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, Lock, Eye, AlertTriangle } from "lucide-react"

export default function HomePage() {
  return (
    <div className="container mx-auto px-4 py-8">
      {/* Hero Section */}
      <div className="text-center mb-12">
        <div className="flex justify-center mb-6">
          <div className="relative">
            <Shield className="h-20 w-20 text-blue-500 pulse-glow" />
            <div className="absolute inset-0 animate-ping">
              <Shield className="h-20 w-20 text-blue-500 opacity-20" />
            </div>
          </div>
        </div>
        <h1 className="text-4xl md:text-6xl font-bold bg-gradient-to-r from-blue-400 via-purple-500 to-cyan-400 bg-clip-text text-transparent mb-4">
          Communication_LTD
        </h1>
        <p className="text-xl text-muted-foreground mb-2">Secure Ticket Management System</p>
        <p className="text-lg text-muted-foreground">Advanced Customer Support & Security Platform</p>

        {/* Environment Badge */}
        <div className="flex justify-center mt-6">
          <Badge variant={process.env.NEXT_PUBLIC_VULN_MODE === "true" ? "destructive" : "default"} className="text-sm">
            {process.env.NEXT_PUBLIC_VULN_MODE === "true" ? (
              <>
                <AlertTriangle className="h-4 w-4 mr-2" />
                Vulnerability Mode: Active
              </>
            ) : (
              <>
                <Lock className="h-4 w-4 mr-2" />
                Secure Mode: Active
              </>
            )}
          </Badge>
        </div>

        {/* API Status */}
        <div className="text-center mt-6">
          <p className="text-center text-muted-foreground">
            API Base: {process.env.NEXT_PUBLIC_API_BASE || "http://localhost:5000"}
          </p>
        </div>
      </div>

      {/* Feature Cards */}
      <div className="grid md:grid-cols-3 gap-6 mb-12">
        <Card className="border-blue-500/20 bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-blue-500" />
              Advanced Security
            </CardTitle>
            <CardDescription>Enterprise-grade security features</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>• JWT Authentication with HttpOnly Cookies</li>
              <li>• CSRF Protection (Double-Submit Pattern)</li>
              <li>• Rate Limiting & Request Monitoring</li>
              <li>• Comprehensive Audit Logging</li>
            </ul>
          </CardContent>
        </Card>

        <Card className="border-purple-500/20 bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Eye className="h-5 w-5 text-purple-500" />
              Monitoring & Control
            </CardTitle>
            <CardDescription>Real-time system oversight</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>• Real-time Request Tracking</li>
              <li>• User Activity Monitoring</li>
              <li>• Security Event Logging</li>
              <li>• Performance Analytics</li>
            </ul>
          </CardContent>
        </Card>

        <Card className="border-cyan-500/20 bg-card/50 backdrop-blur">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-cyan-500" />
              Ticket Management
            </CardTitle>
            <CardDescription>Comprehensive support system</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>• Customer Support Tickets</li>
              <li>• Priority & Category Management</li>
              <li>• Comment System</li>
              <li>• Status Tracking</li>
            </ul>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
