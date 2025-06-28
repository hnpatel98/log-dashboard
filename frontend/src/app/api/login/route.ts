import { NextRequest, NextResponse } from 'next/server';
import { sign } from 'jsonwebtoken';

export async function POST(request: NextRequest) {
  try {
    const { username, password } = await request.json();

    // Validate credentials against environment variables
    const validUsername = process.env.ADMIN_USERNAME;
    const validPassword = process.env.ADMIN_PASSWORD;

    if (username === validUsername && password === validPassword) {
      // Create JWT token
      const token = sign(
        { username, role: 'admin' },
        process.env.JWT_SECRET || 'fallback-secret',
        { expiresIn: '1h' }
      );

      // Create response with HTTP-only cookie
      const response = NextResponse.json({ success: true, message: 'Login successful' });
      
      response.cookies.set('auth-token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600, // 1 hour
        path: '/',
      });

      return response;
    } else {
      return NextResponse.json(
        { success: false, message: 'Invalid credentials' },
        { status: 401 }
      );
    }
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
} 