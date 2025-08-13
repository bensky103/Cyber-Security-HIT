"use client"

import { useQuery } from "@tanstack/react-query"
import api from "@/lib/api"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Loader2, MessageSquare } from "lucide-react"
import DOMPurify from "dompurify"

interface Comment {
  id: number
  content: string
  created_at: string
  updated_at: string
  user: {
    id: number
    username: string
    role: string
  }
}

interface CommentsListProps {
  ticketId: string
}

export function CommentsList({ ticketId }: CommentsListProps) {
  const {
    data: comments,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["ticket-comments", ticketId],
    queryFn: async (): Promise<Comment[]> => {
  const response = await api.get(`/tickets/${ticketId}/comments`)
  const data = response.data
  // Support either { comments: [] } or raw []
  if (Array.isArray(data)) return data as Comment[]
  return (data && data.comments) || []
    },
    enabled: !!ticketId,
  })

  const renderCommentContent = (content: string) => {
    if (process.env.NEXT_PUBLIC_VULN_MODE === "true") {
      // In vulnerability mode, render content as-is without sanitization
      return <div className="text-sm text-muted-foreground" dangerouslySetInnerHTML={{ __html: content }} />
    } else {
      // In patched mode, sanitize HTML content before rendering
      const sanitizedContent = DOMPurify.sanitize(content)
      return <div className="text-sm text-muted-foreground" dangerouslySetInnerHTML={{ __html: sanitizedContent }} />
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-4">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        Loading comments...
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-4">
        <p className="text-red-500 text-sm">Failed to load comments</p>
      </div>
    )
  }

  if (!comments || comments.length === 0) {
    return (
      <div className="text-center py-8">
        <MessageSquare className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
        <p className="text-muted-foreground">No comments yet</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {comments.map((comment) => (
        <Card key={comment.id} className="border-l-4 border-l-blue-500">
          <CardContent className="pt-4">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="font-medium text-sm">{comment.user.username}</span>
                <Badge variant="outline" className="text-xs">
                  {comment.user.role}
                </Badge>
              </div>
              <span className="text-xs text-muted-foreground">{new Date(comment.created_at).toLocaleString()}</span>
            </div>
            {renderCommentContent(comment.content)}
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
