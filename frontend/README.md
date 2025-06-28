# Log Dashboard Frontend

A modern, responsive web interface for analyzing and monitoring application logs built with Next.js, TypeScript, and Tailwind CSS.

## Features

- 🔐 **Basic Authentication** - Simple login system for user access
- 📁 **File Upload** - Drag and drop or click to upload log files (.txt, .log)
- 📊 **Log Analysis** - Automatic parsing and analysis of log entries
- 📈 **Visual Charts** - Interactive pie charts showing log level distribution
- 📋 **Data Tables** - Detailed view of all log entries with filtering
- 📱 **Responsive Design** - Works seamlessly on desktop and mobile devices

## Tech Stack

- **Framework**: Next.js 14 with App Router
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Icons**: Lucide React
- **Charts**: Recharts
- **UI Components**: Custom components with modern design

## Getting Started

### Prerequisites

- Node.js 18+ 
- npm or yarn

### Installation

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the development server:
   ```bash
   npm run dev
   ```

4. Open [http://localhost:3000](http://localhost:3000) in your browser.

## Usage

### Authentication
- Enter any username and password to access the dashboard
- This is a basic implementation - in production, you'd want proper authentication

### Uploading Log Files
1. Click on the upload area or drag and drop files
2. Supported formats: `.txt`, `.log`
3. Multiple files can be uploaded simultaneously
4. Files are processed client-side for immediate analysis

### Viewing Analysis
- **Summary Statistics**: Total logs, errors, warnings, info, and debug counts
- **Visual Chart**: Pie chart showing log level distribution
- **Time Range**: Start and end timestamps of the log data
- **Top Errors**: Most frequent error messages
- **Log Table**: Detailed view of all log entries with source file information

### Log Parsing
The application automatically parses log entries looking for:
- Timestamps in format: `YYYY-MM-DD HH:MM:SS`
- Log levels: ERROR, WARN, INFO, DEBUG
- If no timestamp is found, current time is used
- If no level is found, INFO is assigned

## Project Structure

```
src/
├── app/
│   ├── layout.tsx          # Root layout with metadata
│   ├── page.tsx            # Main dashboard page
│   └── globals.css         # Global styles
├── components/
│   ├── LoginForm.tsx       # Authentication form
│   ├── FileUpload.tsx      # File upload component
│   └── LogChart.tsx        # Chart visualization
└── types/                  # TypeScript type definitions
```

## Development

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint

### Adding New Features

1. **New Components**: Create in `src/components/`
2. **New Pages**: Add to `src/app/` following Next.js App Router conventions
3. **Styling**: Use Tailwind CSS classes for consistent design
4. **Types**: Define interfaces in component files or create dedicated type files

## Deployment

### Vercel (Recommended)
1. Push code to GitHub
2. Connect repository to Vercel
3. Deploy automatically

### Other Platforms
1. Build the project: `npm run build`
2. Deploy the `out` directory to your hosting platform

## Customization

### Styling
- Modify `tailwind.config.js` for theme customization
- Update `src/app/globals.css` for global styles
- Use Tailwind utility classes for component styling

### Log Parsing
- Update the parsing logic in `src/app/page.tsx` for different log formats
- Add support for additional log levels
- Implement custom timestamp parsing

### Authentication
- Replace the basic authentication with a proper auth system
- Integrate with services like Auth0, NextAuth.js, or custom backend

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is part of the Log Dashboard application.
