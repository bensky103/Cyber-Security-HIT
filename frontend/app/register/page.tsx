"use client"

import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { usePasswordPolicy, useRegister } from "@/lib/api-hooks"
import { createRegisterSchema } from "@/lib/validation-schemas"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Shield, CheckCircle, XCircle } from "lucide-react"
import Link from "next/link"
import { useRouter } from "next/navigation"

export default function RegisterPage() {
  const router = useRouter()
  const { data: policy, isLoading: policyLoading } = usePasswordPolicy()
  const registerMutation = useRegister()

  const schema = createRegisterSchema(policy)
  const form = useForm({
    resolver: zodResolver(schema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
      confirmPassword: "",
      role: "customer" as const,
    },
  })

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
    setValue,
  } = form
  const password = watch("password")

  const onSubmit = async (data: any) => {
    try {
      await registerMutation.mutateAsync({
        username: data.username,
        email: data.email,
        password: data.password,
        role: data.role,
      })
      router.push("/login?message=Registration successful. Please log in.")
    } catch (error: any) {
      // Error handling is done by the mutation
    }
  }

  // Password policy validation indicators
  const getPasswordValidation = () => {
    if (!policy || !password) return []

    const validations = [
      {
        rule: `At least ${policy.min_length} characters`,
        valid: password.length >= policy.min_length,
      },
    ]

    if (policy.require_uppercase) {
      validations.push({
        rule: "One uppercase letter",
        valid: /[A-Z]/.test(password),
      })
    }

    if (policy.require_lowercase) {
      validations.push({
        rule: "One lowercase letter",
        valid: /[a-z]/.test(password),
      })
    }

    if (policy.require_numbers) {
      validations.push({
        rule: "One number",
        valid: /\d/.test(password),
      })
    }

    if (policy.require_special_chars) {
      validations.push({
        rule: `One special character (${policy.special_chars})`,
        valid: new RegExp(`[${policy.special_chars.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}]`).test(password),
      })
    }

    return validations
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-500" />
          </div>
          <CardTitle className="text-2xl">Create Account</CardTitle>
          <CardDescription>Register for Communication_LTD Secure System</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                {...register("username")}
                placeholder="Enter username"
                disabled={registerMutation.isPending}
              />
              {errors.username && <p className="text-sm text-destructive">{errors.username.message}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                {...register("email")}
                placeholder="Enter email address"
                disabled={registerMutation.isPending}
              />
              {errors.email && <p className="text-sm text-destructive">{errors.email.message}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="role">Role</Label>
              <Select onValueChange={(value) => setValue("role", value as any)} defaultValue="customer">
                <SelectTrigger>
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="customer">Customer</SelectItem>
                  <SelectItem value="support">Support</SelectItem>
                  <SelectItem value="admin">Admin</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                {...register("password")}
                placeholder="Enter password"
                disabled={registerMutation.isPending}
              />
              {errors.password && <p className="text-sm text-destructive">{errors.password.message}</p>}

              {/* Password Policy Indicators */}
              {policy && password && (
                <div className="mt-2 space-y-1">
                  <p className="text-xs text-muted-foreground">Password Requirements:</p>
                  {getPasswordValidation().map((validation, index) => (
                    <div key={index} className="flex items-center gap-2 text-xs">
                      {validation.valid ? (
                        <CheckCircle className="h-3 w-3 text-green-500" />
                      ) : (
                        <XCircle className="h-3 w-3 text-red-500" />
                      )}
                      <span className={validation.valid ? "text-green-500" : "text-red-500"}>{validation.rule}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                type="password"
                {...register("confirmPassword")}
                placeholder="Confirm password"
                disabled={registerMutation.isPending}
              />
              {errors.confirmPassword && <p className="text-sm text-destructive">{errors.confirmPassword.message}</p>}
            </div>

            {registerMutation.error && (
              <Alert variant="destructive">
                <AlertDescription>
                  {registerMutation.error?.response?.data?.message ||
                    registerMutation.error?.response?.data?.error ||
                    "Registration failed. Please try again."}
                </AlertDescription>
              </Alert>
            )}

            <Button type="submit" className="w-full" disabled={registerMutation.isPending || policyLoading}>
              {registerMutation.isPending ? "Creating Account..." : "Create Account"}
            </Button>

            <div className="text-center text-sm">
              <span className="text-muted-foreground">Already have an account? </span>
              <Link href="/login" className="text-primary hover:underline">
                Sign in
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
