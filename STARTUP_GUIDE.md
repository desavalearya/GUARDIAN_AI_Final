# Guardian AI - Startup Guide

## ✅ Issues Fixed

1. **Dashboard Syntax Error**: Fixed `<pre>` tag placement in App.tsx
2. **Docker Cleanup Script**: Created to free up C drive space

---

## Step-by-Step Startup Instructions

### Step 1: Start Docker Desktop

1. Open **Docker Desktop** from Windows Start menu
2. Wait for Docker to show "Docker Desktop is running" (whale icon in system tray should be stable, not animating)
3. Verify by opening PowerShell and running:
   ```powershell
   docker ps
   ```
   Should show a table (even if empty), not an error

---

### Step 2: Clean Up Docker (Free Space)

**IMPORTANT**: Do this BEFORE starting your project to free up space!

```powershell
cd D:\SMTP_NEW_PROJECT
.\scripts\cleanup_docker.ps1
```

**What this does**:
- Stops all running containers
- Removes stopped containers
- Removes unused images
- Removes unused volumes
- Clears build cache
- **Can free 5-20 GB** depending on how much Docker has accumulated

**Note**: This will remove old images from other projects too, so you may need to rebuild those later.

---

### Step 3: Start Guardian AI

```powershell
cd D:\SMTP_NEW_PROJECT
docker compose up --build -d
```

**Wait 3-5 minutes** for:
- Images to build
- ML dependencies to install (scikit-learn, transformers, torch, etc.)
- npm packages to install (frontend)
- Services to become healthy

---

### Step 4: Verify Services Started

```powershell
docker compose ps
```

**Expected output**: All 8 services should show "Up" status:
- postgres (healthy)
- redis (healthy)
- api
- worker
- milter
- postfix
- mail-client
- dashboard

---

### Step 5: Check Logs (If Issues)

```powershell
# Check specific service logs
docker compose logs api --tail 50
docker compose logs dashboard --tail 50
docker compose logs mail-client --tail 50

# Watch live logs
docker compose logs -f
```

---

### Step 6: Access Applications

| Application | URL | Login |
|-------------|-----|-------|
| **Mail Client** | http://localhost:5173 | `user@example.com` / `changeme1` |
| **SOC Dashboard** | http://localhost:5174 | `analyst@example.com` / `changeme1` |
| **API Docs** | http://localhost:8000/docs | N/A (JWT required) |

---

### Step 7: Test ML Models in Dashboard

1. Go to http://localhost:5174
2. Login as `analyst@example.com`
3. Click **Model Lab** tab
4. Test each model:

#### Test Text Phishing:
- Paste: `"URGENT! Your account will be suspended unless you verify now!"`
- Click "Analyze Text"
- Should show ~99% phishing probability

#### Test Office Document:
- Upload any `.docx` or `.xlsx` file
- Should show malicious probability + feature analysis

#### Test PDF:
- Upload any `.pdf` file
- Should show malicious probability + structure analysis

**Note**: First model load takes 10-30 seconds (models are lazy-loaded)

---

## Troubleshooting

### Issue: "Docker Desktop is not running"

**Solution**:
1. Start Docker Desktop from Windows Start menu
2. Wait for it to fully start (whale icon stable in tray)
3. Try again

---

### Issue: Frontend shows compile error

**Solution**: Already fixed! The syntax error in dashboard App.tsx has been corrected.

---

### Issue: Port already in use

**Error**: `Bind for 0.0.0.0:5173 failed: port is already allocated`

**Solution**:
```powershell
# Stop the conflicting service
docker compose down

# Or kill the process using that port
netstat -ano | findstr "5173"
# Note the PID, then:
taskkill /PID <PID> /F

# Then restart
docker compose up -d
```

---

### Issue: Models not loading / "Model not found"

**Solution**: Verify model files exist:
```powershell
Get-ChildItem -Path D:\SMTP_NEW_PROJECT\models -Recurse -Include "*.joblib","*.bin" | Format-Table Name, Length
```

Should show:
- `office_malware_rf.joblib` (~294 KB)
- `pdf_malware_rf.joblib` (~6.4 MB)
- `training_args.bin` (~5 KB)

---

### Issue: C drive still full after cleanup

**Additional cleanup options**:

1. **Docker Desktop Settings**:
   - Open Docker Desktop → Settings → Resources → Disk image location
   - Consider moving Docker data to D drive

2. **WSL cleanup** (if using WSL2):
   ```powershell
   wsl --shutdown
   # This releases WSL memory back to Windows
   ```

3. **Windows cleanup**:
   - Run Disk Cleanup (cleanmgr)
   - Clear `C:\Users\<YourName>\AppData\Local\Temp`
   - Clear browser caches

---

## Quick Commands Reference

```powershell
# Start
docker compose up -d

# Rebuild and start (after code changes)
docker compose up --build -d

# Stop
docker compose stop

# Stop and remove containers
docker compose down

# Stop and remove everything including data
docker compose down -v

# View logs
docker compose logs -f

# Check disk usage
docker system df

# Cleanup Docker
.\scripts\cleanup_docker.ps1
```

---

## Docker Space Management

### Check Space Usage:
```powershell
docker system df
```

### What Takes Space:
- **Images**: Built layers (~2-5 GB for this project)
- **Containers**: Running instances (~100 MB each)
- **Volumes**: Postgres data, opendkim keys (~500 MB)
- **Build Cache**: Intermediate layers (~1-10 GB)

### Regular Maintenance:
Run cleanup script weekly if working with multiple Docker projects:
```powershell
.\scripts\cleanup_docker.ps1
```

---

## Summary

✅ **Syntax Error**: Fixed  
✅ **Cleanup Script**: Created  
✅ **Startup Guide**: Complete  

**Now**:
1. Start Docker Desktop
2. Run cleanup script: `.\scripts\cleanup_docker.ps1`
3. Start project: `docker compose up --build -d`
4. Test at http://localhost:5173 and http://localhost:5174

---

## Support

If you encounter issues:
1. Check logs: `docker compose logs -f`
2. Verify Docker is running: `docker ps`
3. Check disk space: `docker system df`
4. Try cleanup: `.\scripts\cleanup_docker.ps1`
