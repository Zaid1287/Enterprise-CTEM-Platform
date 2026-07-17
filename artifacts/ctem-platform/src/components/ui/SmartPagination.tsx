import { cn } from "@/lib/utils";
import { ChevronsLeft, ChevronsRight, ChevronLeft, ChevronRight } from "lucide-react";

interface SmartPaginationProps {
  page: number;
  totalPages: number;
  totalItems?: number;
  pageSize?: number;
  itemLabel?: string;
  onPageChange: (p: number) => void;
  className?: string;
  compact?: boolean;
}

function buildPageRange(page: number, totalPages: number): (number | "...")[] {
  if (totalPages <= 1) return [];

  const always = new Set<number>();

  // Always include first page
  always.add(1);

  // Always include last 3 pages
  for (let i = Math.max(1, totalPages - 2); i <= totalPages; i++) {
    always.add(i);
  }

  // Include current ± 2 window
  for (let i = Math.max(1, page - 2); i <= Math.min(totalPages, page + 2); i++) {
    always.add(i);
  }

  const sorted = Array.from(always).sort((a, b) => a - b);

  const result: (number | "...")[] = [];
  for (let i = 0; i < sorted.length; i++) {
    if (i > 0 && sorted[i] - sorted[i - 1] > 1) {
      result.push("...");
    }
    result.push(sorted[i]);
  }

  return result;
}

export function SmartPagination({
  page,
  totalPages,
  totalItems,
  pageSize,
  itemLabel = "items",
  onPageChange,
  className,
  compact = false,
}: SmartPaginationProps) {
  if (totalPages <= 1) return null;

  const pages = buildPageRange(page, totalPages);

  const from = pageSize && totalItems != null ? (page - 1) * pageSize + 1 : null;
  const to = pageSize && totalItems != null ? Math.min(page * pageSize, totalItems) : null;

  return (
    <div className={cn("flex items-center justify-between pt-1", className)}>
      {/* Left: item range info */}
      {totalItems != null && from != null && to != null ? (
        <p className="text-xs text-muted-foreground">
          Showing {from}–{to} of {totalItems} {itemLabel}
        </p>
      ) : totalItems != null ? (
        <p className="text-xs text-muted-foreground">
          Page {page} of {totalPages} · {totalItems} {itemLabel}
        </p>
      ) : (
        <p className="text-xs text-muted-foreground">
          Page {page} of {totalPages}
        </p>
      )}

      {/* Right: page buttons */}
      <div className="flex items-center gap-0.5">
        {/* Go to first */}
        <button
          disabled={page === 1}
          onClick={() => onPageChange(1)}
          title="First page"
          className={cn(
            "h-7 w-7 flex items-center justify-center rounded-md text-xs transition-colors",
            "border border-border",
            page === 1
              ? "opacity-40 cursor-not-allowed text-muted-foreground bg-transparent"
              : "text-muted-foreground hover:text-foreground hover:bg-accent cursor-pointer",
          )}
        >
          <ChevronsLeft className="w-3.5 h-3.5" />
        </button>

        {/* Previous */}
        <button
          disabled={page === 1}
          onClick={() => onPageChange(page - 1)}
          title="Previous page"
          className={cn(
            "h-7 w-7 flex items-center justify-center rounded-md text-xs transition-colors",
            "border border-border",
            page === 1
              ? "opacity-40 cursor-not-allowed text-muted-foreground bg-transparent"
              : "text-muted-foreground hover:text-foreground hover:bg-accent cursor-pointer",
          )}
        >
          <ChevronLeft className="w-3.5 h-3.5" />
        </button>

        {/* Page numbers with ellipsis */}
        {pages.map((p, idx) =>
          p === "..." ? (
            <span
              key={`ellipsis-${idx}`}
              className="h-7 w-7 flex items-center justify-center text-xs text-muted-foreground/60 select-none"
            >
              …
            </span>
          ) : (
            <button
              key={p}
              onClick={() => onPageChange(p)}
              className={cn(
                "h-7 min-w-[28px] px-1 flex items-center justify-center rounded-md text-xs font-medium transition-colors border",
                p === page
                  ? "bg-primary text-primary-foreground border-primary shadow-sm"
                  : "border-border text-muted-foreground hover:text-foreground hover:bg-accent cursor-pointer",
              )}
            >
              {p}
            </button>
          ),
        )}

        {/* Next */}
        <button
          disabled={page === totalPages}
          onClick={() => onPageChange(page + 1)}
          title="Next page"
          className={cn(
            "h-7 w-7 flex items-center justify-center rounded-md text-xs transition-colors",
            "border border-border",
            page === totalPages
              ? "opacity-40 cursor-not-allowed text-muted-foreground bg-transparent"
              : "text-muted-foreground hover:text-foreground hover:bg-accent cursor-pointer",
          )}
        >
          <ChevronRight className="w-3.5 h-3.5" />
        </button>

        {/* Go to last */}
        <button
          disabled={page === totalPages}
          onClick={() => onPageChange(totalPages)}
          title="Last page"
          className={cn(
            "h-7 w-7 flex items-center justify-center rounded-md text-xs transition-colors",
            "border border-border",
            page === totalPages
              ? "opacity-40 cursor-not-allowed text-muted-foreground bg-transparent"
              : "text-muted-foreground hover:text-foreground hover:bg-accent cursor-pointer",
          )}
        >
          <ChevronsRight className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
}
