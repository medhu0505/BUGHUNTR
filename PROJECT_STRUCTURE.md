# BUGHUNTR Project Structure

## Overview
BUGHUNTR is a full-stack bug bounty hunting platform with a React frontend and Flask backend for discovering and managing security vulnerabilities.

## Directory Structure

```
BUGHUNTR/
├── docs/                          # Documentation
│   ├── README.md                 # Main documentation
│   ├── README_*.md               # Localized documentation
│   ├── SETUP.md                  # Setup instructions
│   └── CODEBASE_AUDIT_ISSUES.md # Known issues and audit notes
│
├── src/                           # Frontend (React + Vite)
│   ├── components/               # React components
│   │   ├── ui/                  # Base UI components (shadcn/ui)
│   │   ├── AppSidebar.tsx       # Navigation sidebar
│   │   ├── DashboardLayout.tsx  # Main layout wrapper
│   │   ├── NavLink.tsx          # Navigation link component
│   │   ├── SeverityBadge.tsx    # Severity indicator
│   │   ├── StatsCard.tsx        # Statistics display
│   │   ├── TerminalLog.tsx      # Log viewer component
│   │   └── ...
│   ├── pages/                    # Page components
│   │   ├── DashboardOverview.tsx # Main dashboard
│   │   ├── ScannerPage.tsx      # Scanner interface
│   │   ├── ReportsCenter.tsx    # Reports management
│   │   ├── ScanHistoryPage.tsx  # Scan history
│   │   ├── AboutPage.tsx        # About page
│   │   └── ...
│   ├── hooks/                    # Custom React hooks
│   │   ├── use-toast.ts         # Toast notifications
│   │   └── use-mobile.tsx       # Mobile detection
│   ├── lib/                      # Utilities and helpers
│   │   ├── api-client.ts        # API communication
│   │   ├── data-service.ts      # Data management
│   │   ├── mock-data.ts         # Mock data for testing
│   │   └── utils.ts             # Utility functions
│   ├── App.tsx                   # Root app component
│   ├── main.tsx                  # App entry point
│   ├── App.css                   # Global styles
│   ├── index.css                 # Base styles
│   └── vite-env.d.ts             # Vite types
│
├── backend/                       # Flask backend
│   ├── app.py                    # Flask application
│   ├── db.py                     # Database models
│   ├── scanners.py               # Scanner implementations
│   ├── requirements.txt           # Python dependencies
│   └── instance/                 # Flask instance folder (generated)
│
├── public/                        # Static assets
│   └── robots.txt                # SEO robots file
│
├── scripts/                       # Utility scripts
│   ├── run.bat                   # Windows startup script
│   ├── start.sh                  # Unix startup script
│   └── README.md                 # Scripts documentation
│
├── Configuration Files
│   ├── package.json              # Node.js dependencies
│   ├── vite.config.ts            # Vite build config
│   ├── tsconfig.json             # TypeScript config
│   ├── tailwind.config.ts         # Tailwind CSS config
│   ├── postcss.config.js         # PostCSS config
│   ├── eslint.config.js          # ESLint config
│   ├── components.json           # Shadcn/ui components config
│   └── .env.example              # Environment variables template
│
├── Deployment Files
│   ├── Procfile                  # Heroku/Railway process definition
│   ├── railway.json              # Railway deployment config
│   ├── runtime.txt               # Python runtime version
│   └── .nvmrc                    # Node.js version
│
├── .gitignore                     # Git ignore rules
├── .git/                          # Git repository
├── index.html                     # HTML entry point
│
└── [Generated/Ignored]
    ├── node_modules/             # Node packages (ignored)
    ├── dist/                     # Build output (ignored)
    ├── .venv/ / backend/venv/    # Python virtual environments (ignored)
    ├── .env.local                # Local environment config (ignored)
    └── *.log                     # Log files (ignored)
```

## Technology Stack

### Frontend
- **Framework**: React 18.3
- **Build Tool**: Vite
- **Styling**: Tailwind CSS + Shadcn/UI
- **Routing**: React Router v6
- **State Management**: React Query (TanStack)
- **UI Components**: Radix UI
- **Utilities**: Date-fns, Lucide Icons, Sonner (Toast)

### Backend
- **Framework**: Flask
- **Database**: SQLite (with instance/bbh.db)
- **Security**: Blinker, Werkzeug
- **HTTP**: Requests library
- **ORM**: SQLAlchemy

### Development Tools
- **Linting**: ESLint
- **Package Managers**: npm, Bun
- **Version Control**: Git

## Key Features

1. **Dashboard Overview**: Real-time vulnerability metrics and statistics
2. **Scanner Interface**: Multiple security scanning tools
3. **Report Management**: Centralized vulnerability reporting
4. **Scan History**: Track and review historical scans
5. **Severity Tracking**: Color-coded vulnerability severity levels
6. **Terminal Logging**: Live scan output visualization

## Getting Started

### Prerequisites
- Node.js (v18+)
- Python (v3.12+)
- npm or Bun

### Setup

1. **Frontend Setup**
   ```bash
   npm install
   npm run dev
   ```

2. **Backend Setup**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   python app.py
   ```

See [docs/SETUP.md](docs/SETUP.md) for detailed instructions.

## Important Notes

- Virtual environments (`venv/`, `.venv/`) are not tracked in git - recreate them after cloning
- Environment variables: Copy `.env.example` to `.env.local` and configure
- Large binaries (nuclei.exe) should be downloaded separately if needed
- Database file (`backend/instance/bbh.db`) is generated at runtime

## Development

- Frontend runs on `http://localhost:5173` (Vite dev server)
- Backend API runs on `http://localhost:5000` (Flask)
- Frontend proxies API calls to backend

## Deployment

- Configured for Railway and Heroku deployments
- See `Procfile` and `railway.json` for deployment configuration
- Build: `npm run build`
- Preview: `npm run preview`

## Contributing

See [docs/README.md](docs/README.md) for contribution guidelines.

## Project Status

- **Version**: 3.2.0
- **Status**: Active Development
- **Issues**: See [docs/CODEBASE_AUDIT_ISSUES.md](docs/CODEBASE_AUDIT_ISSUES.md)
