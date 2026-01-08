"""
CFSSL Process Manager

Manages the CFSSL binary as a subprocess, handling startup, health monitoring,
and automatic restarts.
"""

import atexit
import logging
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from django.conf import settings

logger = logging.getLogger(__name__)


class CFSSLManager:
    """
    Manages the CFSSL server process.

    Handles:
    - Binary detection (PATH or configured location)
    - Starting CFSSL with appropriate arguments
    - Health monitoring with automatic restart
    - Graceful shutdown
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern to ensure only one manager instance."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        self._process = None
        self._monitor_thread = None
        self._shutdown_event = threading.Event()
        self._restart_count = 0
        self._max_restarts = 5
        self._restart_window = 300  # 5 minutes
        self._restart_times = []

        # Configuration - loaded dynamically
        self._binary_path = None
        self._health_check_interval = 10  # seconds

    def _get_config(self) -> dict:
        """
        Get configuration from database settings, falling back to Django settings.

        Returns dict with: auto_start, binary_path, host, port
        """
        # Try to get from database first
        try:
            from core.models import AppSettings
            app_settings = AppSettings.get()
            return {
                'auto_start': app_settings.cfssl_auto_start,
                'binary_path': app_settings.cfssl_binary_path or None,
                'host': app_settings.cfssl_host,
                'port': app_settings.cfssl_port,
            }
        except Exception:
            # Fall back to Django settings / environment variables
            return {
                'auto_start': getattr(settings, 'CFSSL_AUTO_START', True),
                'binary_path': getattr(settings, 'CFSSL_BINARY_PATH', None) or None,
                'host': getattr(settings, 'CFSSL_HOST', 'localhost'),
                'port': int(getattr(settings, 'CFSSL_PORT', 8888)),
            }

    @property
    def _port(self) -> int:
        return self._get_config()['port']

    @property
    def _host(self) -> str:
        return self._get_config()['host']

    @property
    def _auto_start(self) -> bool:
        return self._get_config()['auto_start']

    def find_binary(self, configured_path: str | None = None) -> str | None:
        """
        Find the CFSSL binary.

        Checks in order:
        1. Provided configured_path parameter
        2. Database/environment configured path
        3. System PATH
        4. Common installation locations

        Args:
            configured_path: Optional path to check first (avoids database access)

        Returns:
            Path to binary or None if not found
        """
        # Check provided path first (avoids database access during startup)
        if configured_path is None:
            configured_path = self._get_config()['binary_path']
        if configured_path and os.path.isfile(configured_path):
            if os.access(configured_path, os.X_OK):
                return configured_path
            logger.warning(f"CFSSL binary at {configured_path} is not executable")

        # Check system PATH
        binary = shutil.which('cfssl')
        if binary:
            return binary

        # Check common locations
        common_paths = [
            '/usr/local/bin/cfssl',
            '/usr/bin/cfssl',
            Path.home() / 'go' / 'bin' / 'cfssl',
            Path.home() / '.local' / 'bin' / 'cfssl',
        ]

        for path in common_paths:
            path = Path(path)
            if path.is_file() and os.access(path, os.X_OK):
                return str(path)

        return None

    def is_running(self) -> bool:
        """Check if CFSSL process is running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    def health_check(self) -> bool:
        """
        Check if CFSSL is healthy by hitting the health endpoint.

        Returns:
            True if healthy, False otherwise
        """
        import requests

        try:
            url = f"http://{self._host}:{self._port}/api/v1/cfssl/health"
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except requests.exceptions.Timeout:
            logger.warning("CFSSL health check timed out (>5s)")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"CFSSL health check connection error: {e}")
            return False
        except Exception as e:
            logger.warning(f"CFSSL health check error: {type(e).__name__}: {e}")
            return False

    def start(self, host: str | None = None, port: int | None = None,
              binary_path: str | None = None) -> bool:
        """
        Start the CFSSL server process.

        Args:
            host: Override host (avoids database access during startup)
            port: Override port (avoids database access during startup)
            binary_path: Override binary path (avoids database access during startup)

        Returns:
            True if started successfully, False otherwise
        """
        if self.is_running():
            logger.info("CFSSL is already running (managed by this process)")
            return True

        # Check if CFSSL is already running externally (e.g., started by another worker)
        # Retry a few times to handle race conditions with multiple workers starting
        for attempt in range(3):
            if self.health_check():
                logger.info("CFSSL is already running (external process)")
                return True
            if attempt < 2:
                time.sleep(0.5)  # Brief wait before retry

        # Find binary (pass configured path to avoid database access if provided)
        self._binary_path = self.find_binary(configured_path=binary_path)
        if not self._binary_path:
            logger.error(
                "CFSSL binary not found. Install CFSSL or set CFSSL_BINARY_PATH. "
                "Install with: brew install cfssl (macOS) or go install github.com/cloudflare/cfssl/cmd/...@latest"
            )
            return False

        logger.info(f"Found CFSSL binary at: {self._binary_path}")

        # Use provided values or fall back to config (database/settings)
        start_host = host if host is not None else self._host
        start_port = port if port is not None else self._port

        # Build command
        cmd = [
            self._binary_path,
            'serve',
            '-address', start_host,
            '-port', str(start_port),
        ]

        # Note: We don't load the CA certificate here to avoid database access
        # during app initialization. CFSSL will start without a CA and can
        # be used for key generation. Certificate signing uses the CA cert/key
        # passed directly via the API.

        # Start process
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # Detach from parent
            )

            # Wait a moment for startup
            time.sleep(1)

            if not self.is_running():
                stderr = self._process.stderr.read().decode() if self._process.stderr else ""
                # Check if another process started CFSSL (race condition)
                if self.health_check():
                    logger.info("CFSSL is already running (started by another process)")
                    self._process = None  # We don't own this process
                    return True
                logger.error(f"CFSSL failed to start: {stderr}")
                return False

            logger.info(f"CFSSL started on {start_host}:{start_port} (PID: {self._process.pid})")

            # Start health monitor
            self._start_monitor()

            # Register shutdown handler
            atexit.register(self.stop)

            return True

        except Exception as e:
            logger.error(f"Failed to start CFSSL: {e}")
            return False

    def stop(self) -> None:
        """Stop the CFSSL server process gracefully."""
        self._shutdown_event.set()

        # Don't try to join if we're being called from the monitor thread itself
        # (e.g., during restart from health check failure)
        if self._monitor_thread and self._monitor_thread.is_alive():
            if threading.current_thread() is not self._monitor_thread:
                self._monitor_thread.join(timeout=5)

        if self._process and self.is_running():
            logger.info("Stopping CFSSL...")
            try:
                self._process.terminate()
                try:
                    self._process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    logger.warning("CFSSL did not stop gracefully, killing...")
                    self._process.kill()
                    self._process.wait()
                logger.info("CFSSL stopped")
            except Exception as e:
                logger.error(f"Error stopping CFSSL: {e}")

        self._process = None

    def restart(self) -> bool:
        """Restart the CFSSL server."""
        logger.info("Restarting CFSSL...")
        self.stop()
        time.sleep(1)
        return self.start()

    def _should_restart(self) -> bool:
        """
        Check if we should attempt a restart based on restart limits.

        Prevents restart loops by limiting restarts within a time window.
        """
        now = time.time()

        # Remove old restart times outside the window
        self._restart_times = [t for t in self._restart_times if now - t < self._restart_window]

        if len(self._restart_times) >= self._max_restarts:
            logger.error(
                f"CFSSL has restarted {self._max_restarts} times in the last "
                f"{self._restart_window} seconds. Not restarting again."
            )
            return False

        self._restart_times.append(now)
        return True

    def _start_monitor(self) -> None:
        """Start the health monitoring thread."""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return

        self._shutdown_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _monitor_loop(self) -> None:
        """Background thread that monitors CFSSL health."""
        consecutive_failures = 0
        max_consecutive_failures = 3

        while not self._shutdown_event.is_set():
            self._shutdown_event.wait(self._health_check_interval)

            if self._shutdown_event.is_set():
                break

            if not self.is_running():
                logger.warning("CFSSL process is not running (process exited)")
                consecutive_failures = max_consecutive_failures
            elif not self.health_check():
                consecutive_failures += 1
                # Log process status for debugging
                pid = self._process.pid if self._process else None
                logger.warning(
                    f"CFSSL health check failed ({consecutive_failures}/{max_consecutive_failures}) "
                    f"[PID={pid}, process_alive={self.is_running()}]"
                )
            else:
                consecutive_failures = 0

            if consecutive_failures >= max_consecutive_failures:
                if self._should_restart():
                    logger.warning("CFSSL appears unhealthy, attempting restart...")
                    if self.restart():
                        consecutive_failures = 0
                    else:
                        logger.error("Failed to restart CFSSL")
                        break
                else:
                    break

    def _find_cfssl_pid(self) -> int | None:
        """Find the PID of a running CFSSL process."""
        # If we own the process, return its PID
        if self._process and self.is_running():
            return self._process.pid
        # Otherwise try to find it via pgrep
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'cfssl serve'],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Return first PID if multiple found
                return int(result.stdout.strip().split()[0])
        except Exception:
            pass
        return None

    def get_status(self) -> dict:
        """Get current status of CFSSL manager."""
        # Check actual health - works across all workers regardless of which one
        # started CFSSL (only one worker owns self._process)
        healthy = self.health_check()
        return {
            'running': healthy,  # If healthy, it's running
            'healthy': healthy,
            'pid': self._find_cfssl_pid() if healthy else None,
            'binary_path': self._binary_path,
            'host': self._host,
            'port': self._port,
            'restart_count': len(self._restart_times),
        }


# Global instance
_manager = None


def get_cfssl_manager() -> CFSSLManager:
    """Get the global CFSSL manager instance."""
    global _manager
    if _manager is None:
        _manager = CFSSLManager()
    return _manager


def start_cfssl() -> bool:
    """Start CFSSL if auto-start is enabled."""
    manager = get_cfssl_manager()
    if manager._auto_start:
        return manager.start()
    return True


def stop_cfssl() -> None:
    """Stop CFSSL."""
    manager = get_cfssl_manager()
    manager.stop()
