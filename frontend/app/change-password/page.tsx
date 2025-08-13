"use client"

import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { usePasswordPolicy, useChangePassword } from "@/lib/api-hooks"
import { createChangePasswordSchema } from "@/lib/validation-schemas"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Shield, CheckCircle, XCircle } from "lucide-react"
import { useAuthContext } from "@/lib/auth-context"
import { useRouter } from "next/navigation"
import { useEffect } from "react"

export default function ChangePasswordPage() {
  const router = useRouter()
  const { isAuthenticated } = useAuthContext()
  const { data: policy, isLoading: policyLoading } = usePasswordPolicy()
  const changePasswordMutation = useChangePassword()

  useEffect(() => {
    if (!isAuthenticated) {
      router.push("/login")
    }
  }, [isAuthenticated, router])

  const schema = createChangePasswordSchema(policy)
  const form = useForm({
    resolver: zodResolver(schema),
    defaultValues: {
      oldPassword: "",
      newPassword: "",
      confirmNewPassword: "",
    },
  })

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
    reset,
  } = form
  const newPassword = watch("newPassword")

  const onSubmit = async (data: any) => {
    try {
      await changePasswordMutation.mutateAsync({
        oldPassword: data.oldPassword,
        newPassword: data.newPassword,
      })
      reset()
      // Show success message
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

  if (!isAuthenticated) {
    return null
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-500" />
          </div>
          <CardTitle className="text-2xl">Change Password</CardTitle>
          <CardDescription>Update your account password</CardDescription>
        </CardHeader>
        <CardContent>
          {changePasswordMutation.isSuccess && (
            <Alert className="mb-4">
              <AlertDescription>Password changed successfully!</AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="oldPassword">Current Password</Label>
              <Input
                id="oldPassword"
                type="password"
                {...register("oldPassword")}
                placeholder="Enter current password"
                disabled={changePasswordMutation.isPending}
              />
              {errors.oldPassword && <p className="text-sm text-destructive">{errors.oldPassword.message}</p>}
            </div>

            <div className="space-y-2">
              <Label htmlFor="newPassword">New Password</Label>
              <Input
                id="newPassword"
                type="password"
                {...register("newPassword")}
                placeholder="Enter new password"
                disabled={changePasswordMutation.isPending}
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
                disabled={changePasswordMutation.isPending}
              />
              {errors.confirmNewPassword && (
                <p className="text-sm text-destructive">{errors.confirmNewPassword.message}</p>
              )}
            </div>

            {changePasswordMutation.error && (
              <Alert variant="destructive">
                <AlertDescription>
                  {changePasswordMutation.error?.response?.data?.message ||
                    "Failed to change password. Please try again."}
                </AlertDescription>
              </Alert>
            )}

            <Button type="submit" className="w-full" disabled={changePasswordMutation.isPending || policyLoading}>
              {changePasswordMutation.isPending ? "Changing Password..." : "Change Password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
