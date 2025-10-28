'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Loader2 } from 'lucide-react';

export default function ThreatsPage() {
  const router = useRouter();

  useEffect(() => {
    // Redirect to main dashboard with alerts tab active
    router.push('/?tab=alerts');
  }, [router]);

  return (
    <div className="flex h-screen items-center justify-center">
      <Loader2 className="h-8 w-8 animate-spin" />
      <span className="ml-2">Redirecting to threats...</span>
    </div>
  );
}
