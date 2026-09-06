# Docker Cleanup Script - Free up C drive space
# Run this AFTER starting Docker Desktop

Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  DOCKER CLEANUP SCRIPT" -ForegroundColor Yellow
Write-Host "  Removes unused images, containers, volumes, and build cache" -ForegroundColor Yellow
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
Write-Host "[1/7] Checking Docker status..." -ForegroundColor Cyan
try {
    docker ps | Out-Null
    Write-Host "  Docker is running!" -ForegroundColor Green
} catch {
    Write-Host "  ERROR: Docker Desktop is not running!" -ForegroundColor Red
    Write-Host "  Please start Docker Desktop and try again." -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Show current disk usage
Write-Host "[2/7] Current Docker disk usage:" -ForegroundColor Cyan
docker system df
Write-Host ""

# Stop all running containers
Write-Host "[3/7] Stopping all running containers..." -ForegroundColor Cyan
$running = docker ps -q
if ($running) {
    docker stop $running
    Write-Host "  Stopped $($running.Count) container(s)" -ForegroundColor Green
} else {
    Write-Host "  No running containers" -ForegroundColor Yellow
}
Write-Host ""

# Remove all stopped containers
Write-Host "[4/7] Removing stopped containers..." -ForegroundColor Cyan
$stopped = docker ps -aq
if ($stopped) {
    docker rm $stopped
    Write-Host "  Removed $($stopped.Count) container(s)" -ForegroundColor Green
} else {
    Write-Host "  No stopped containers" -ForegroundColor Yellow
}
Write-Host ""

# Remove unused images
Write-Host "[5/7] Removing unused images..." -ForegroundColor Cyan
docker image prune -a -f
Write-Host ""

# Remove unused volumes
Write-Host "[6/7] Removing unused volumes..." -ForegroundColor Cyan
docker volume prune -f
Write-Host ""

# Remove build cache
Write-Host "[7/7] Removing build cache..." -ForegroundColor Cyan
docker builder prune -a -f
Write-Host ""

# Show final disk usage
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  CLEANUP COMPLETE!" -ForegroundColor Green
Write-Host "=" -NoNewline -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

Write-Host "Final Docker disk usage:" -ForegroundColor Cyan
docker system df
Write-Host ""

Write-Host "Space reclaimed! Your C drive now has more free space." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. cd D:\SMTP_NEW_PROJECT" -ForegroundColor White
Write-Host "  2. docker compose up --build -d" -ForegroundColor White
Write-Host ""
