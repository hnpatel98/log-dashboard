import { NextResponse } from 'next/server';

export async function POST() {
  try {
    // Create response and clear the auth cookie
    const response = NextResponse.json({ success: true, message: 'Logout successful' });
    
    response.cookies.delete('auth-token');

    return response;
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 