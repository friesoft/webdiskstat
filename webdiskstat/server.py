#!/usr/bin/env python3
import os
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

# Mount templates as static directory
from fastapi.staticfiles import StaticFiles
try:
    from importlib import resources
    static_path = resources.files("webdiskstat").joinpath("templates")
except Exception:
    static_path = Path(__file__).parent / "templates"

app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Global State
scan_lock = asyncio.Lock()
is_scanning = False
last_scan_error: Optional[str] = None
last_scan_completed_time: Optional[float] = None
next_scan_scheduled_time: Optional[float] = None
server_args = None

async def run_scan(force: bool = False, sub_path: Optional[str] = None) -> bool:
    """
    Executes GDU or NCDU, captures raw JSON output, and compiles the
    interactive HTML report in-process in Python.
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
        
        cached_root = None
        output_path = Path(server_args.output)
        if sub_path and output_path.exists():
            try:
                import json
                from webdiskstat.compiler import deserialize_report_payload
                payload_data = json.loads(output_path.read_text(encoding="utf-8"))
                cached_root = deserialize_report_payload(payload_data.get("payload", ""))
            except Exception as exc:
                print(f"[Server] Failed to deserialize cached tree: {exc}", file=sys.stderr)
                pass

        if cached_root is None and sub_path:
            print(f"[Server] Cache unavailable, falling back to full scan instead of subscan for {sub_path}", file=sys.stderr)
            sub_path = None
            
        scan_msg = f"Starting disk scan for {sub_path}..." if sub_path else "Starting disk scan..."
        print(f"[Server] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {scan_msg}", file=sys.stderr)
        
        try:
            # Build GDU command
            gdu_cmd = ["gdu"]
            if server_args.gdu_ignore_dirs:
                gdu_cmd.extend(["-i", server_args.gdu_ignore_dirs])
                
            target_path = server_args.scan_dir
            if sub_path:
                if sub_path.startswith(server_args.scan_dir):
                    target_path = sub_path
                else:
                    target_path = os.path.join(server_args.scan_dir, sub_path.lstrip("/"))
                
            gdu_cmd.extend(["-o-", target_path])
            
            print(f"[Server] Spawning scanner process: {' '.join(gdu_cmd)}", file=sys.stderr)
            
            # Run the process asynchronously
            p = await asyncio.create_subprocess_exec(
                gdu_cmd[0],
                *gdu_cmd[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion and capture stdout/stderr
            stdout, stderr = await p.communicate()
            
            if p.returncode != 0:
                err_msg = stderr.decode("utf-8", errors="replace").strip()
                raise RuntimeError(f"Scanner process failed (exit {p.returncode}): {err_msg}")
                
            print("[Server] Scan complete. Parsing GDU/NCDU JSON structure...", file=sys.stderr)
            import json
            raw_data = json.loads(stdout)
            
            print("[Server] Serializing report data in-process...", file=sys.stderr)
            from webdiskstat.compiler import normalize_export, report_data_payload
            
            if sub_path and cached_root is not None:
                if sub_path.rstrip("/") == server_args.scan_dir.rstrip("/"):
                    root = normalize_export(raw_data)
                else:
                    sub_root = normalize_export(raw_data)
                    from webdiskstat.compiler import find_and_replace_subtree, add_totals
                    found, delta = find_and_replace_subtree(cached_root, sub_path, sub_root)
                    if not found:
                        print(f"[Server] Warning: sub_path {sub_path} not found in cached tree. Tree not updated.", file=sys.stderr)
                    else:
                        print(f"[Server] Replaced sub_tree at {sub_path}, delta size: {delta}", file=sys.stderr)
                        add_totals(cached_root)
                    root = cached_root
            else:
                root = normalize_export(raw_data)
                
            payload = report_data_payload(root)
            
            # Write to output file
            output_path.parent.mkdir(parents=True, exist_ok=True)
            import json
            output_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
            
            elapsed = time.time() - start_time
            last_scan_completed_time = time.time()
            if server_args.scan_interval > 0:
                next_scan_scheduled_time = last_scan_completed_time + server_args.scan_interval
            else:
                next_scan_scheduled_time = None
                
            print(f"[Server] Report written successfully to {output_path} in {elapsed:.2f} seconds.", file=sys.stderr)
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
async def trigger_rescan(background_tasks: BackgroundTasks, path: Optional[str] = None):
    """Queues a manual rescan task asynchronously if one is not already running."""
    if is_scanning or scan_lock.locked():
        raise HTTPException(status_code=409, detail="Scan already in progress")
        
    background_tasks.add_task(run_scan, force=True, sub_path=path)
    return {"status": "scanning", "message": "Manual rescan triggered."}

@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def serve_report():
    """Serves the decoupled static HTML skeleton directly."""
    try:
        from importlib import resources
        html_content = resources.files("webdiskstat.templates").joinpath("template.html").read_text(encoding="utf-8")
    except Exception:
        template_dir = Path(__file__).parent / "templates"
        html_content = (template_dir / "template.html").read_text(encoding="utf-8")
        
    return HTMLResponse(
        content=html_content,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
        }
    )

@app.get("/api/report")
async def get_report():
    """Returns the generated report JSON structure."""
    output_path = Path(server_args.output)
    if not output_path.exists():
        raise HTTPException(
            status_code=503,
            detail="Scan report data has not been generated yet. Please wait..."
        )
    try:
        import json
        return Response(
            content=output_path.read_bytes(),
            media_type="application/json",
            headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"}
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to read report data: {exc}")

def main():
    global server_args
    parser = argparse.ArgumentParser(description="webdiskstat - Asynchronous Web Server Daemon")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8080")), help="Web server port (default: 8080)")
    parser.add_argument("--scan-dir", default=os.getenv("SCAN_DIR", "/scan"), help="Directory to analyze (default: /scan)")
    parser.add_argument("--output", default=os.getenv("OUTPUT", "reports/report.json"), help="JSON report output path (default: reports/report.json)")
    parser.add_argument("--scan-interval", type=int, default=int(os.getenv("SCAN_INTERVAL", "86400")), help="Periodic scan interval in seconds (default: 86400)")
    parser.add_argument("--force-initial-scan", type=lambda x: (str(x).lower() == 'true'), default=(os.getenv("FORCE_INITIAL_SCAN", "false").lower() == 'true'), help="Force scan on startup")
    parser.add_argument("--gdu-ignore-dirs", default=os.getenv("GDU_IGNORE_DIRS", ""), help="Comma separated subdirectory exclusions")
    
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
