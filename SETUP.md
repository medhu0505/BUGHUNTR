# BUGHUNTR v1 - Setup & Running Guide

## Quick Start

### Prerequisites
- Node.js 18+ (for frontend)
- Python 3.8+ (for backend)

### Frontend Setup

1. **Install dependencies:**
   ```bash
   cd BUGHUNTRv1
   npm install
   ```

2. **Start development server:**
   ```bash
   npm run dev
   ```
   Frontend runs on `http://localhost:8080`

### Backend Setup

1. **Create virtual environment:**
   ```bash
   cd BUGHUNTRv1
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   # OR
   source .venv/bin/activate  # Mac/Linux
   ```

2. **Install dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```

3. **Run backend:**
   ```bash
   python app.py
   ```
   Backend runs on `http://localhost:5000`

### Architecture

The frontend automatically connects to the backend through the API configured in `.env.local`:
```
VITE_API_BASE_URL=http://localhost:5000/api
```

**Frontend endpoints** (what the UI calls):
- `GET /api/modules` - List available scanners
- `GET /api/findings` - All findings  
- `GET /api/dashboard/stats` - Dashboard stats
- `GET /api/dashboard/activity` - Activity feed
- `GET /api/modules/{id}/config` - Module options
- `POST /api/scans/run` - Run a scan

**Backend implementation** handles:
- Module scanning with real security checks
- Database persistence of findings
- SSE streaming for scan progress
- Activity logging

### Features

✅ Minimalistic clean frontend (removed 37+ unused UI components)
✅ Full backend integration with 10 security scanners
✅ Real-time scan progress via SSE  
✅ Finding persistence with SQLite
✅ CORS enabled for cross-origin requests
✅ Mock data fallback if backend is unavailable

### Building for Production

Frontend:
```bash
npm run build
```

This creates optimized build in `dist/` directory.

### Troubleshooting

**CORS errors:** Make sure backend is running on port 5000
**Module not found:** Verify all dependencies installed with `pip install -r requirements.txt`
**Port conflicts:** Modify port in backend `app.py` if needed (search for `app.run(`)
