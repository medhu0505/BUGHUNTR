# BUGHUNTR - Security Vulnerability Scanner

A minimalistic, full-stack bug hunting and vulnerability scanning platform designed to identify security vulnerabilities across web applications. Scan targets for security vulnerabilities across 10+ modules including subdomain takeover, CORS misconfigurations, API key leaks, and more.

## 🚀 Quick Links

- **🏃 [Get Started](#quick-start)** - Up and running in 5 minutes
- **🚢 [Deploy to Railway](#railway-deployment)** - 1-click production deployment
- **📚 [Full Documentation](#documentation)** - Complete guides and references

## 🚀 Quick Deploy

Ready to deploy? It's easy:

1. Push to GitHub:
   ```bash
   git add . && git commit -m "Initial commit" && git push origin main
   ```

2. Go to [railway.app](https://railway.app) → New Project → Deploy from GitHub
3. Select your repository → Wait 2-5 minutes → Done! 🎉

See [RAILWAY_DEPLOYMENT.md](./RAILWAY_DEPLOYMENT.md) for detailed instructions.

## 🎯 Features

- **10 Security Scanner Modules:**
  - Subdomain Takeover Detection
  - S3/Blob Bucket Configuration Checker
  - CORS Misconfiguration Scanner
  - Sensitive File Exposure Detector
  - API Key Leak Detector
  - Open Redirect Fuzzer
  - Clickjacking Vulnerability Scanner
  - DNS Zone Transfer Detector
  - SPF/DMARC Configuration Checker
  - Rate Limiting Tester

- **📊 Real-time Dashboard** - Visual statistics and vulnerability trends
- **🔍 Detailed Findings** - Comprehensive vulnerability reports with severity levels
- **💾 Persistent Storage** - SQLite database for finding history
- **🎨 Dark Theme UI** - Modern, minimalistic interface
- **⚡ Graceful Fallback** - Uses mock data if backend unavailable
- **🚀 Production Ready** - Full deployment configuration included

## 🏗️ Tech Stack

| Component | Technology |
|-----------|-----------|
| **Frontend** | React 18 + TypeScript + Vite |
| **Styling** | TailwindCSS + Radix UI (minimal) |
| **Visualization** | Recharts |
| **Backend** | Flask + SQLAlchemy |
| **Database** | SQLite (or PostgreSQL) |
| **Deployment** | Railway.app |

## 📋 Prerequisites

- **Node.js:** 18+ ([Download](https://nodejs.org))
- **Python:** 3.8+ ([Download](https://www.python.org))
- **Git:** For version control ([Download](https://git-scm.com))

## 🏃 Quick Start

### Local Development - Frontend

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

Frontend runs on `http://localhost:5173` with hot reload enabled.

### Local Development - Backend

In a **separate terminal**:

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate  # Mac/Linux
# OR
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Start backend
python app.py
```

Backend runs on `http://localhost:5000`.

### Configure Local Environment

Create `.env.local` in the project root:

```
VITE_API_BASE_URL=/api
```

**Note:** This relative path works for both local development and production. It's automatically smart-configured.

## 🚢 Railway Deployment

This application is fully configured for Railway deployment with **zero additional setup** needed.

### Automatic Build Process

Railway will automatically:
1. Install Node dependencies: `npm install`
2. Build frontend: `npm run build`
3. Install Python dependencies: `pip install -r requirements.txt`
4. Start backend: `python app.py`
5. Serve frontend + API from single domain

### What Gets Deployed

- ✅ Frontend React app (compiled to static files)
- ✅ Backend Flask API
- ✅ SQLite database (ephemeral - resets on redeploy)
- ✅ All security scanner modules
- ✅ CORS configuration for production

### Environment Variables (Optional)

In Railway Dashboard → Your Project → Variables:

```
FLASK_ENV=production
DATABASE_URL=sqlite:///bbh.db
PORT=5000
```

These are optional. Default values work fine.

### Persistent Database

By default, Railway's filesystem is ephemeral. For persistent data:

1. Add PostgreSQL plugin in Railway dashboard
2. Railway automatically sets `DATABASE_URL`
3. Your data persists across redeployments

See [RAILWAY_DEPLOYMENT.md](./RAILWAY_DEPLOYMENT.md) for detailed guide.

## 🔌 API Endpoints

The backend provides these REST API endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/modules` | List available scanner modules |
| GET | `/api/findings` | Get all findings |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| GET | `/api/dashboard/activity` | Activity feed |
| GET | `/api/modules/{id}/config` | Module configuration |
| POST | `/api/scans/run` | Execute security scan |

**Example Request:**
```bash
curl -X POST http://localhost:5000/api/scans/run \
  -H "Content-Type: application/json" \
  -d '{"moduleId":"subdomain-takeover","target":"example.com"}'
```

## Project Structure

```
.
├── src/                    # Frontend source
│   ├── components/        # React components
│   ├── pages/            # Page components
│   ├── lib/              # Utilities and services
│  📁 Project Structure

```
.
├── src/                          # Frontend React application
│   ├── components/              # Reusable React components
│   │   ├── AppSidebar.tsx      # Navigation sidebar
│   │   ├── DashboardLayout.tsx  # Main layout wrapper
│   │   ├── StatsCard.tsx        # Statistics card component
│   │   ├── SeverityBadge.tsx    # Severity indicator badge
│   │   └── TerminalLog.tsx      # Scan output display
│   ├── pages/                   # Page components
│   │   ├── DashboardOverview.tsx # Main dashboard
│   │   ├── ScannerPage.tsx      # Scanner interface
│   │   ├── ReportsCenter.tsx    # Reports viewer
│   │   └── NotFound.tsx         # 404 page
│   ├── lib/                     # Utilities
│   │   ├── api-client.ts        # API communication
│   │   ├── data-service.ts      # Backend API calls
│   │   ├── mock-data.ts         # Fallback mock data
│   │   └── utils.ts             # Utilities
│   ├── hooks/                   # Custom React hooks
│   ├── App.tsx                  # Main app component
│   ├── main.tsx                 # App entry point
│   └── index.css                # Global styles
│
├── backend/                      # Flask backend server
│   ├── app.py                  # Main Flask application
│   ├── db.py                   # Database models
│   ├── scanners.py             # Security scanner implementations
│   ├── requirements.txt         # Python dependencies
│   └── bbh.db                  # SQLite database (generated)
│
├── public/                      # Static assets
├── dist/                        # Build output (generated)
├── package.json                 # Frontend dependencies
├── vite.config.ts              # Vite configuration
├── tsconfig.json               # TypeScript configuration
├── tailwind.config.ts          # TailwindCSS configuration
├── Procfile                    # Railway deployment config
├── railway.json                # Railway settings
├── .env.example                # Environment variables template
├── .env.local                  # Local environment (not committed)
├── .nvmrc                      # Node.js version
├── runtime.txt                 # Python version
└── README.md                   # This file
```

## 📚 Usage Guide

### Scanning a Target

1. **Select Module:** Choose a security scanner from the sidebar (10 available)
2. **Enter Target:** Input the target URL/domain
3. **Configure Options:** Customize scan parameters if needed
4. **Run Scan:** Click "Run Scan" button
5. **Review Results:** Vulnerabilities appear in real-time

### Understanding Severity Levels

- 🔴 **Critical** - Immediate action required
- 🟠 **High** - Should be addressed soon
- 🟡 **Medium** - Important to fix
- 🔵 **Low** - Minor issue
- ⚪ **Info** - Informational

### Generating Reports

1. Go to **Reports Center**
2. Filter by severity, module, or status
3. Click **Download** to export as JSON or CSV

## 🏗️ Build & Deployment Scripts

### Frontend

| Command | Purpose |
|---------|---------|
| `npm run dev` | Start development server with hot reload |
| `npm run build` | Build for production (~760 KB) |
| `npm run preview` | Preview production build locally |
| `npm run lint` | Run ESLint |

### Backend

| Command | Purpose |
|---------|---------|
| `python app.py` | Start development server |
| `pip install -r requirements.txt` | Install dependencies |

## 🔧 Key Features Explained

### Graceful Fallback
If the backend is unavailable, the frontend automatically uses mock data instead of showing errors. This ensures the app remains usable during development or testing.

### Module Mapping
The frontend uses standardized module IDs that are automatically mapped to backend scanner implementations, allowing flexibility in naming conventions and easy extensibility.

### Real-time Scanning
Security scans run asynchronously on the backend. Findings are persisted to SQLite and returned to the frontend for display. Results update in real-time.

### Architecture
- **Single Domain:** Both frontend and backend served from one URL in production
- **Relative API Paths:** `/api` works everywhere (local and production)
- **Static Files:** Frontend compiled once, delivered efficiently
- **Persistent Storage:** SQLite by default, PostgreSQL for production scale

## 🚨 Troubleshooting

### Frontend Issues

**CORS Errors:**
- Ensure backend is running on `http://localhost:5000`
- Check `VITE_API_BASE_URL` is set to `/api` or `http://localhost:5000/api`

**Module Not Loading:**
- Clear browser cache (Ctrl+Shift+Del)
- Run `npm install` again
- Check browser console for errors

**Styles Not Appearing:**
- Restart dev server: `npm run dev`
- Clear cache if needed

### Backend Issues

**Port in Use:**
- Change port in `backend/app.py`: `app.run(port=5001)`
- Or kill process using port

**Database Error:**
- Delete `backend/bbh.db` to reset
- Ensure write permissions in `backend/` directory
- Check Python version: `python --version` (needs 3.8+)

**Module Import Error:**
- Verify all files in `backend/scanners.py`
- Run `pip install -r requirements.txt` again

**Dependencies Missing:**
- Frontend: `npm install`
- Backend: `pip install -r requirements.txt`

### Production Issues (Railway)

**Build Fails:**
- Check Railway build logs (Dashboard → Deployments)
- Verify `package.json` has all required scripts
- Ensure `backend/requirements.txt` is valid

**API Not Responding:**
- Check Flask error logs in Railway
- Verify `VITE_API_BASE_URL=/api` in production
- Ensure no port conflicts

**Database Not Persisting:**
- Default SQLite resets on redeploy (expected)
- Add PostgreSQL plugin for persistence

## 🔒 Security & Best Practices

### Development
- Environment variables in `.env.local` (not committed)
- Mock data for testing without backend
- Local HTTP for development

### Production
- HTTPS automatic (Railway provides)
- Environment secrets in Railway dashboard
- Database: PostgreSQL recommended for data persistence
- CORS configured for single domain
- No personal data stored unnecessarily

### Scanning
- All vulnerabilities automatically identified by scanners
- Results should be manually verified before action
- No data sent to external services
- SQLite database is local to application

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see [LICENSE](./LICENSE) file for details.

## 📞 Support & Documentation

- **Complete Deployment Guide:** [RAILWAY_DEPLOYMENT.md](./RAILWAY_DEPLOYMENT.md)
- **Pre-Deployment Checklist:** [DEPLOYMENT_CHECKLIST.md](./DEPLOYMENT_CHECKLIST.md)
- **Setup Details:** [SETUP.md](./SETUP.md)
- **GitHub Issues:** Create an issue for bugs and features
- **Questions:** Check documentation or open a discussion

## 🎉 Next Steps

1. **Local Development:**
   ```bash
   npm install && npm run dev
   # In another terminal:
   cd backend && python -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python app.py
   ```

2. **Test Everything:**
   - Frontend loads at `http://localhost:5173`
   - Backend responds at `http://localhost:5000/api/modules`
   - Scan works from UI

3. **Deploy to Railway:**
   ```bash
   git add . && git commit -m "Ready to deploy" && git push origin main
   # Then: railway.app → New Project → Deploy from GitHub
   ```

---

**Made with ❤️ for security researchers and developers**

**Last Updated:** April 14, 2026 | **Status:** Production Ready ✅