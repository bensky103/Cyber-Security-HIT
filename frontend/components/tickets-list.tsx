"use client"

import { useState } from "react"
import { useTickets } from "@/lib/api-hooks"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Loader2, Ticket, ChevronLeft, ChevronRight, Eye } from "lucide-react"
import Link from "next/link"

export function TicketsList() {
  const [currentPage, setCurrentPage] = useState(1)
  const perPage = 10
  const { data, isLoading, error } = useTickets(currentPage, perPage)

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-8">
          <Loader2 className="h-6 w-6 animate-spin mr-2" />
          Loading tickets...
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="py-8">
          <p className="text-red-500 text-center">Failed to load tickets</p>
        </CardContent>
      </Card>
    )
  }

  const tickets = data?.tickets || []
  const totalPages = Math.ceil((data?.total || 0) / perPage)

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case "open":
        return "default"
      case "in_progress":
        return "secondary"
      case "resolved":
        return "outline"
      case "closed":
        return "destructive"
      default:
        return "default"
    }
  }

  const getPriorityColor = (priority: string) => {
    switch (priority.toLowerCase()) {
      case "high":
        return "destructive"
      case "medium":
        return "secondary"
      case "low":
        return "outline"
      default:
        return "default"
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid gap-4">
        {tickets.length === 0 ? (
          <Card>
            <CardContent className="py-8">
              <p className="text-center text-muted-foreground">No tickets found</p>
            </CardContent>
          </Card>
        ) : (
          tickets.map((ticket: any) => (
            <Card key={ticket.id} className="border-cyan-500/20">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Ticket className="h-5 w-5 text-cyan-500" />
                      Ticket #{ticket.id}
                    </CardTitle>
                    <CardDescription className="mt-1">{ticket.subject}</CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Badge variant={getStatusColor(ticket.status)}>{ticket.status}</Badge>
                    <Badge variant={getPriorityColor(ticket.priority)}>{ticket.priority}</Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <p className="text-sm text-muted-foreground">Category: {ticket.category}</p>
                    <p className="text-sm text-muted-foreground">
                      Created: {new Date(ticket.created_at).toLocaleDateString()}
                    </p>
                  </div>
                  <Link href={`/tickets/${ticket.id}`}>
                    <Button variant="outline" size="sm">
                      <Eye className="h-4 w-4 mr-2" />
                      View Details
                    </Button>
                  </Link>
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
