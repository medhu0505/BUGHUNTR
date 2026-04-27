# BUGHUNTR

A comprehensive vulnerability scanning and bug bounty management platform designed for security professionals and bug bounty hunters.

## Overview

BUGHUNTR is a full-stack web application that streamlines vulnerability discovery, assessment, and reporting. It provides a unified interface for managing security scans, organizing findings, and generating professional reports for bug bounty programs like HackerOne.

### Key Features

- **Multi-Scanner Integration** - Run various security checks including CORS analysis, subdomain enumeration, DNS validation, rate limiting tests, and more
- **Real-Time Scan Progress** - SSE-powered live updates during active scans
- **Centralized Finding Management** - Organize, track, and manage all vulnerability findings in one place
- **Professional Report Generation** - HackerOne-compatible Markdown formatting for findings
- **Dashboard Analytics** - Monitor scan history, vulnerability trends, and asset coverage
- **Persistent Data Storage** - SQLite database for reliable finding storage and retrieval
- **RESTful API** - Clean, well-structured backend API for extensibility
- **Modern Frontend** - React-based responsive UI with real-time updates

## Architecture

### Frontend Stack
- **React 18** - UI component framework
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first styling
- **React Router** - Client-side routing
- **TanStack Query** - Server state management
- **Vite** - Fast build tooling

### Backend Stack
- **Flask** - Python web framework
- **SQLAlchemy** - ORM for database operations
- **SQLite** - Data persistence
- **RESTful API** - Standard HTTP endpoints

### Security Scanners
1. **Subdomain Takeover** - CNAME analysis with hosting provider detection
2. **S3 Bucket Enumeration** - AWS S3 & Azure Blob detection
3. **CORS Analysis** - Cross-origin resource sharing validation
4. **Sensitive File Detection** - Common configuration and credential files
5. **API Key Leak Detection** - Regex-based secret scanning
6. **Open Redirect Testing** - Redirect parameter validation
7. **Clickjacking Analysis** - Frame options and CSP validation
8. **DNS Zone Transfer** - AXFR enumeration
9. **SPF/DMARC Validation** - Email security policy analysis
10. **Rate Limiting Tests** - Service throttling detection

## Installation & Setup

### Prerequisites
- Node.js 18+ (frontend)
- Python 3.8+ (backend)
- Git

### Quick Start

#### 1. Clone Repository
```bash
git clone https://github.com/medhu0505/BUGHUNTR.git
cd BUGHUNTR
```

#### 2. Frontend Setup
```bash
npm install
npm run dev
```
Frontend will be available at `http://localhost:8080`

#### 3. Backend Setup
```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate
# Mac/Linux
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```
Backend API will be available at `http://localhost:5000/api`

#### 4. Configure Frontend Connection
Create/update `.env.local`:
```env
VITE_API_BASE_URL=http://localhost:5000/api
```

## API Endpoints

### Core Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/modules` | List available scanners |
| POST | `/api/scans/run` | Start a new scan |
| GET | `/api/scans/{id}` | Get scan details |
| GET | `/api/findings` | List all findings |
| GET | `/api/findings/{id}` | Get specific finding |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| GET | `/api/dashboard/activity` | Recent activity feed |
| GET | `/stream/{scanId}` | Server-sent events for scan progress |

## Configuration

### Environment Variables

**Backend (.env)**
```env
FLASK_ENV=production
DATABASE_URL=sqlite:///app.db
```

**Frontend (.env.local)**
```env
VITE_API_BASE_URL=https://api.bughuntr.com/api
```

## Building for Production

### Frontend Build
```bash
npm run build
```
Outputs optimized bundle to `dist/` directory.

### Backend Deployment
```bash
# Install production dependencies
pip install -r requirements.txt

# Run with production server (gunicorn recommended)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 backend.app:app
```

## Deployment

### Docker Deployment
```bash
docker build -t bughuntr .
docker run -p 8080:8080 -p 5000:5000 bughuntr
```

### Cloud Deployment
The project includes configuration for Railway deployment:
- `Procfile` - Process file for deployment
- `runtime.txt` - Python version specification
- `railway.json` - Railway platform configuration

## Project Structure

```
BUGHUNTR/
├── src/                    # Frontend React application
│   ├── components/         # Reusable UI components
│   ├── pages/              # Page components
│   ├── hooks/              # Custom React hooks
│   ├── lib/                # Utility functions and services
│   └── main.tsx            # Entry point
├── backend/                # Flask backend
│   ├── app.py              # Flask application setup
│   ├── db.py               # Database models
│   ├── scanners.py         # Security scanning implementations
│   └── requirements.txt    # Python dependencies
├── public/                 # Static assets
├── package.json            # Frontend dependencies
├── tsconfig.json           # TypeScript configuration
├── vite.config.ts          # Vite build configuration
└── tailwind.config.ts      # Tailwind CSS configuration
```

## Development Workflow

### Running in Development Mode
```bash
# Terminal 1: Frontend (Hot reload)
npm run dev

# Terminal 2: Backend (Flask development server)
cd backend && python app.py
```

### Building & Testing
```bash
# Lint frontend code
npm run lint

# Build production bundle
npm run build

# Preview production build locally
npm run preview
```

## API Response Format

### Finding Structure
```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "asset": "https://example.com",
  "module": "cors-analysis",
  "finding": "CORS misconfiguration detected",
  "severity": "high",
  "status": "new",
  "evidence": {
    "detail": "CORS headers allow * origin"
  },
  "h1_report": "## CORS Misconfiguration\n\n### Description\n...",
  "vulnerable_objects": [
    {
      "url": "https://example.com/api/users",
      "type": "endpoint",
      "description": "Allows arbitrary origin"
    }
  ],
  "timestamp": "2026-04-27T10:30:00Z"
}
```

## Security Considerations

- Run BUGHUNTR within authorized networks only
- Always obtain proper authorization before scanning assets
- Ensure confidential findings are handled securely
- Use HTTPS in production environments
- Implement proper authentication for production deployments
- Database backups recommended for findings preservation

## Performance

- SSE streaming for real-time scan updates
- Efficient database indexing for findings
- Frontend optimized with code splitting and tree-shaking
- Backend request handling with connection pooling

## License

This project is proprietary software.

## Contact & Support

For inquiries, feature requests, or technical support, please contact the development team.

---

**BUGHUNTR** - Professional vulnerability management for security teams.
