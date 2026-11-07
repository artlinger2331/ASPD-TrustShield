export function Skeleton({ className }) {
  return (
    <div
      className={cn(
        "animate-pulse rounded-md bg-gradient-to-r from-white/5 via-white/10 to-white/5 bg-[length:200%_100%]",
        className
      )}
    />
  );
}

export function SkeletonText({ lines = 3, className }) {
  return (
    <div className={cn("flex flex-col gap-3", className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <Skeleton key={i} className={i === lines - 1 ? "w-2/3" : "w-full"} />
      ))}
    </div>
  );
}
