"use client";

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import ClientWrapper from '../components/ClientWrapper';

export default function HomePage() {
  const router = useRouter();

  useEffect(() => {
    router.push('/login');
  }, [router]);

  return (
    <ClientWrapper>
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900">Redirecting...</h1>
          <p className="text-gray-600">Please wait while we redirect you to the login page.</p>
        </div>
      </div>
    </ClientWrapper>
  );
}
