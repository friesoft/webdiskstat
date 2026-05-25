#!/usr/bin/env python3
import sys
import argparse
import asyncio
import time
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Response, BackgroundTasks
from fastapi.responses import HTMLResponse, PlainTextResponse
import uvicorn

app = FastAPI(
    title="webdiskstat-server",
    description="Dynamic backend API and report server for webdiskstat"
)

# Global State
scan_lock = asyncio.Lock()
is_scanning = False
last_scan_error: Optional[str] = None
last_scan_completed_time: Optional[float] = None
next_scan_scheduled_time: Optional[float] = None
server_args = None

async def run_scan(force: bool = False) -> bool:
    """
    Executes the disk scanning pipeline asynchronously.
    If force is False, skips execution if a scan is already running.
    """
    global is_scanning, last_scan_error, last_scan_completed_time, next_scan_scheduled_time
    
    # Try to acquire lock. If force is False, skip if already scanning.
    if not force and scan_lock.locked():
        print("[Server] Scan skipped: Another scan is already in progress.", file=sys.stderr)
        return False
        
    async with scan_lock:
        is_scanning = True
        last_scan_error = None
        start_time = time.time()
        print(f"[Server] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting disk scan...", file=sys.stderr)
        
        try:
            # Build GDU/NCDU command
            scanner = "ncdu" if server_args.input_type == "ncdu" else "gdu"
            gdu_cmd = [scanner]
            if server_args.gdu_ignore_dirs:
                gdu_cmd.extend(["-i", server_args.gdu_ignore_dirs])
            gdu_cmd.extend(["-o-", server_args.scan_dir])
            
            # Build webdiskstat compiler command
            webdiskstat_cmd = ["webdiskstat", "-o", server_args.output]
            if server_args.input_type == "ncdu":
                webdiskstat_cmd.extend(["--input-type", "ncdu"])
                
            # Shell quote command arguments safely to compile a secure pipeline
            import shlex
            scanner_cmd_str = " ".join(shlex.quote(arg) for arg in gdu_cmd)
            compiler_cmd_str = " ".join(shlex.quote(arg) for arg in webdiskstat_cmd)
            pipeline_cmd_str = f"{scanner_cmd_str} | {compiler_cmd_str}"
            
            # Log exact pipeline string
            print(f"[Server] Executing pipeline shell: {pipeline_cmd_str}", file=sys.stderr)
            
            # Run the shell pipeline asynchronously
            p = await asyncio.create_subprocess_shell(
                pipeline_cmd_str,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for the pipeline process to complete
            _, stderr = await p.communicate()
            
            if p.returncode != 0:
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"Scan pipeline failed (exit {p.returncode}): {err_msg}")
                
            elapsed = time.time() - start_time
            last_scan_completed_time = time.time()
            if server_args.scan_interval > 0:
                next_scan_scheduled_time = last_scan_completed_time + server_args.scan_interval
            else:
                next_scan_scheduled_time = None
                
            print(f"[Server] Scan completed successfully in {elapsed:.2f} seconds.", file=sys.stderr)
            return True
            
        except Exception as exc:
            err_str = str(exc)
            print(f"[Server] Scan failed: {err_str}", file=sys.stderr)
            last_scan_error = err_str
            return False
        finally:
            is_scanning = False

async def periodic_scan_loop():
    """Background loop that schedules and runs periodic scans."""
    global next_scan_scheduled_time
    
    # Wait a brief moment for server to initialize and bind
    await asyncio.sleep(2.0)
    
    output_exists = Path(server_args.output).exists()
    if not output_exists or server_args.force_initial_scan:
        print("[Server] Triggering initial disk scan on startup...", file=sys.stderr)
        await run_scan(force=True)
    else:
        print("[Server] Pre-existing HTML report found. Skipping initial scan.", file=sys.stderr)
        # Seed schedule based on current time
        if server_args.scan_interval > 0:
            next_scan_scheduled_time = time.time() + server_args.scan_interval

    if server_args.scan_interval <= 0:
        print("[Server] Periodic scans are disabled (interval <= 0).", file=sys.stderr)
        return

    print(f"[Server] Periodic scans active. Interval: {server_args.scan_interval}s.", file=sys.stderr)
    while True:
        await asyncio.sleep(server_args.scan_interval)
        print("[Server] Triggering scheduled periodic disk scan...", file=sys.stderr)
        await run_scan(force=False)

@app.get("/api/status")
async def get_status():
    """Returns the current state and scan timing metrics."""
    return {
        "status": "scanning" if is_scanning else "idle",
        "error": last_scan_error,
        "last_scan_time": last_scan_completed_time,
        "next_scan_time": next_scan_scheduled_time
    }

@app.post("/api/rescan", status_code=202)
async def trigger_rescan(background_tasks: BackgroundTasks):
    """Queues a manual rescan task asynchronously if one is not already running."""
    if is_scanning or scan_lock.locked():
        raise HTTPException(status_code=409, detail="Scan already in progress")
        
    background_tasks.add_task(run_scan, force=True)
    return {"status": "scanning", "message": "Manual rescan triggered."}

@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def serve_report():
    """Serves the generated HTML report file with strict cache controls."""
    output_path = Path(server_args.output)
    if not output_path.exists():
        return PlainTextResponse(
            content="HTML report not generated yet. Please wait...",
            status_code=503
        )
        
    try:
        html_content = output_path.read_text(encoding="utf-8")
        return HTMLResponse(
            content=html_content,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
            }
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to serve report: {exc}")

def main():
    global server_args
    parser = argparse.ArgumentParser(description="webdiskstat - Asynchronous Web Server Daemon")
    parser.add_argument("--port", type=int, default=8080, help="Web server port (default: 8080)")
    parser.add_argument("--scan-dir", default="/scan", help="Directory to analyze (default: /scan)")
    parser.add_argument("--output", default="index.html", help="HTML report output path (default: index.html)")
    parser.add_argument("--scan-interval", type=int, default=86400, help="Periodic scan interval in seconds (default: 86400)")
    parser.add_argument("--force-initial-scan", type=lambda x: (str(x).lower() == 'true'), default=False, help="Force scan on startup")
    parser.add_argument("--gdu-ignore-dirs", default="", help="Comma separated subdirectory exclusions")
    parser.add_argument("--input-type", choices=("gdu", "ncdu"), default="gdu", help="Scan parser engine (default: gdu)")
    
    server_args = parser.parse_args()
    
    # Seed last_scan_completed_time if output file exists
    global last_scan_completed_time
    output_path = Path(server_args.output)
    if output_path.exists():
        try:
            last_scan_completed_time = output_path.stat().st_mtime
        except Exception:
            pass
    
    # Setup custom loop wrapper to run both uvicorn and our background scheduler
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Spawn background scan loops
    loop.create_task(periodic_scan_loop())
    
    # Configure and run ASGI server
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=server_args.port,
        loop=loop,
        log_level="info",
        access_log=False # Prevent logging spam for status polls
    )
    server = uvicorn.Server(config)
    
    try:
        loop.run_until_complete(server.serve())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

if __name__ == "__main__":
    main()
