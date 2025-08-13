"use client"

import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { usePasswordPolicy, useResetPassword } from "@/lib/api-hooks"
import { createResetPasswordSchema } from "@/lib/validation-schemas"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Shield, CheckCircle, XCircle } from "lucide-react"
import Link from "next/link"
import { useSearchParams, useRouter } from "next/navigation"
import { useEffect } from "react"

export default function ResetPasswordPage() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const token = searchParams.get("token")
  const { data: policy, isLoading: policyLoading } = usePasswordPolicy()
  const resetPasswordMutation = useResetPassword()

  useEffect(() => {
    if (!token) {
      router.push("/forgot-password")
    }
  }, [token, router])

  const schema = createResetPasswordSchema(policy)
  const form = useForm({
    resolver: zodResolver(schema),
    defaultValues: {
      newPassword: "",
      confirmNewPassword: "",
    },
  })

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
  } = form
  const newPassword = watch("newPassword")

  const onSubmit = async (data: any) => {
    if (!token) return

    try {
      await resetPasswordMutation.mutateAsync({
        token,
        new_password: data.newPassword,
      })
      router.push("/login?message=Password reset successful. Please log in with your new password.")
    } catch (error: any) {
      // Error handling is done by the mutation
    }
  }

  // Password policy validation indicators
  const getPasswordValidation = () => {
    if (!policy || !newPassword) return []

    const validations = [
      {
        rule: `At least ${policy.min_length} characters`,
        valid: newPassword.length >= policy.min_length,
      },
    ]

    if (policy.require_uppercase) {
      validations.push({
        rule: "One uppercase letter",
        valid: /[A-Z]/.test(newPassword),
      })
    }

    if (policy.require_lowercase) {
      validations.push({
        rule: "One lowercase letter",
        valid: /[a-z]/.test(newPassword),
      })
    }

    if (policy.require_numbers) {
      validations.push({
        rule: "One number",
        valid: /\d/.test(newPassword),
      })
    }

    if (policy.require_special_chars) {
      validations.push({
        rule: `One special character (${policy.special_chars})`,
        valid: new RegExp(`[${policy.special_chars.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}]`).test(newPassword),
      })
    }

    return validations
  }

  if (!token) {
    return null
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-500" />
          </div>
          <CardTitle className="text-2xl">Set New Password</CardTitle>
          <CardDescription>Enter your new password below</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="newPassword">New Password</Label>
              <Input
                id="newPassword"
                type="password"
                {...register("newPassword")}
                placeholder="Enter new password"
                disabled={resetPasswordMutation.isPending}
              />
              {errors.newPassword && <p className="text-sm text-destructive">{errors.newPassword.message}</p>}

              {/* Password Policy Indicators */}
              {policy && newPassword && (
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
              <Label htmlFor="confirmNewPassword">Confirm New Password</Label>
              <Input
                id="confirmNewPassword"
                type="password"
                {...register("confirmNewPassword")}
                placeholder="Confirm new password"
                disabled={resetPasswordMutation.isPending}
              />
              {errors.confirmNewPassword && (
                <p className="text-sm text-destructive">{errors.confirmNewPassword.message}</p>
              )}
            </div>

            {resetPasswordMutation.error && (
              <Alert variant="destructive">
                <AlertDescription>
                  {resetPasswordMutation.error?.response?.data?.message ||
                    "Failed to reset password. The token may be invalid or expired."}
                </AlertDescription>
              </Alert>
            )}

            <Button type="submit" className="w-full" disabled={resetPasswordMutation.isPending || policyLoading}>
              {resetPasswordMutation.isPending ? "Resetting Password..." : "Reset Password"}
            </Button>

            <div className="text-center text-sm">
              <Link href="/login" className="text-primary hover:underline">
                Back to Sign In
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
