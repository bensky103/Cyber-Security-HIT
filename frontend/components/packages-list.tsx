"use client"

import { useState } from "react"
import { usePackages } from "@/lib/api-hooks"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Loader2, Package, ChevronLeft, ChevronRight } from "lucide-react"

export function PackagesList() {
  const [currentPage, setCurrentPage] = useState(1)
  const perPage = 10
  const { data, isLoading, error } = usePackages(currentPage, perPage)

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading packages...
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="py-8">
          <p className="text-red-500 text-center">Failed to load packages</p>
        </CardContent>
      </Card>
    )
  }

  const packages = data?.packages || []
  const totalPages = Math.ceil((data?.total || 0) / perPage)

  return (
    <div className="space-y-4">
      <div className="grid gap-4">
        {packages.length === 0 ? (
          <Card>
            <CardContent className="py-8">
              <p className="text-center text-muted-foreground">No packages available</p>
            </CardContent>
          </Card>
        ) : (
          packages.map((pkg: any) => (
            <Card key={pkg.id} className="border-purple-500/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Package className="h-5 w-5 text-purple-500" />
                  {pkg.name}
                </CardTitle>
                <CardDescription>{pkg.description}</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <p className="text-2xl font-bold">${pkg.price}</p>
                    <p className="text-sm text-muted-foreground">Duration: {pkg.duration_days} days</p>
                  </div>
                  <Badge variant={pkg.active ? "default" : "secondary"}>{pkg.active ? "Active" : "Inactive"}</Badge>
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
            disabled={currentPage === 1}
          >
            <ChevronLeft className="h-4 w-4" />
            Previous
          </Button>

          <span className="text-sm text-muted-foreground">
            Page {currentPage} of {totalPages}
          </span>

          <Button
            variant="outline"
            size="sm"
            onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
            disabled={currentPage === totalPages}
          >
            Next
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      )}
    </div>
  )
}
