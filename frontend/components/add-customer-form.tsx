"use client"

import { useState } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useToast } from "@/hooks/use-toast"
import { useCreateCustomer } from "@/lib/api-hooks"
import { Loader2, UserPlus } from "lucide-react"

const customerSchema = z.object({
  first_name: z.string().min(1, "First name is required"),
  last_name: z.string().min(1, "Last name is required"),
  phone_number: z.string().min(1, "Phone number is required"),
  address: z.string().optional(),
  city: z.string().optional(),
  postal_code: z.string().optional(),
  country: z.string().optional(),
})

type CustomerFormData = z.infer<typeof customerSchema>

export function AddCustomerForm() {
  const [successMessage, setSuccessMessage] = useState<string>("")
  const { toast } = useToast()
  const createCustomer = useCreateCustomer()

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<CustomerFormData>({
    resolver: zodResolver(customerSchema),
  })

  const onSubmit = async (data: CustomerFormData) => {
    try {
      const result = await createCustomer.mutateAsync(data)
      setSuccessMessage(`Hello, ${data.first_name}! Customer created successfully.`)
      toast({
        title: "Success",
        description: `Customer ${data.first_name} ${data.last_name} has been added.`,
      })
      reset()
    } catch (error: any) {
      toast({
        title: "Error",
        description: error.response?.data?.message || "Failed to create customer",
        variant: "destructive",
      })
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <UserPlus className="h-5 w-5" />
          Add New Customer
        </CardTitle>
        <CardDescription>Enter customer information to create a new account</CardDescription>
      </CardHeader>
      <CardContent>
        {successMessage && (
          <div className="mb-4 p-3 bg-green-500/10 border border-green-500/20 rounded-md">
            <p className="text-green-600 text-sm">{successMessage}</p>
          </div>
        )}

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <Label htmlFor="first_name">First Name *</Label>
              <Input
                id="first_name"
                {...register("first_name")}
                className={errors.first_name ? "border-red-500" : ""}
              />
              {errors.first_name && <p className="text-red-500 text-sm mt-1">{errors.first_name.message}</p>}
            </div>

            <div>
              <Label htmlFor="last_name">Last Name *</Label>
              <Input id="last_name" {...register("last_name")} className={errors.last_name ? "border-red-500" : ""} />
              {errors.last_name && <p className="text-red-500 text-sm mt-1">{errors.last_name.message}</p>}
            </div>
          </div>

          <div>
            <Label htmlFor="phone_number">Phone Number *</Label>
            <Input
              id="phone_number"
              {...register("phone_number")}
              className={errors.phone_number ? "border-red-500" : ""}
            />
            {errors.phone_number && <p className="text-red-500 text-sm mt-1">{errors.phone_number.message}</p>}
          </div>

          <div>
            <Label htmlFor="address">Address</Label>
            <Input id="address" {...register("address")} />
          </div>

          <div className="grid md:grid-cols-3 gap-4">
            <div>
              <Label htmlFor="city">City</Label>
              <Input id="city" {...register("city")} />
            </div>

            <div>
              <Label htmlFor="postal_code">Postal Code</Label>
              <Input id="postal_code" {...register("postal_code")} />
            </div>

            <div>
              <Label htmlFor="country">Country</Label>
              <Input id="country" {...register("country")} />
            </div>
          </div>

          <Button type="submit" disabled={createCustomer.isPending} className="w-full">
            {createCustomer.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Creating Customer...
              </>
            ) : (
              "Add Customer"
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
