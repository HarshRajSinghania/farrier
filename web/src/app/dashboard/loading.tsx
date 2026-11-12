import { Skeleton } from "@/components/ui/misc";

/** Shown while a dashboard page loads: the shape of a page, not a spinner. */
export default function Loading() {
  return (
    <div role="status" aria-label="Loading">
      <Skeleton className="h-10 w-56" />
      <Skeleton className="mt-4 h-4 w-96 max-w-full" />
      <div className="mt-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {Array.from({ length: 4 }, (_, i) => (
          <Skeleton key={i} className="h-28 rounded-lg" />
        ))}
      </div>
      <Skeleton className="mt-4 h-80 rounded-lg" />
    </div>
  );
}
