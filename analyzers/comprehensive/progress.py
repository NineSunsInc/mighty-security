import sys
import time
from threading import Lock


class ProgressTracker:
    """Track and display progress for long-running operations"""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self.total_files = 0
        self.processed_files = 0
        self.current_file = ""
        self.current_phase = ""
        self.phase_start_time = None
        self.scan_start_time = None
        self.last_update_time = 0
        self.update_interval = 0.5
        self.lock = Lock()
        self.file_times = []

    def start_scan(self, total_files: int):
        self.total_files = total_files
        self.processed_files = 0
        self.scan_start_time = time.time()
        self.phase_start_time = time.time()
        self.file_times = []
        if self.verbose:
            print(f"\n📊 Starting scan of {total_files} files...")
            print("━" * 60)

    def start_phase(self, phase_name: str, description: str = ""):
        self.current_phase = phase_name
        self.phase_start_time = time.time()
        if self.verbose:
            print(f"\n🔍 {phase_name}")
            if description:
                print(f"   {description}")

    def update_file(self, file_path: str, file_number: int = None):
        with self.lock:
            current_time = time.time()
            if self.current_file and hasattr(self, "_file_start_time"):
                file_time = current_time - self._file_start_time
                if file_time < 100:
                    self.file_times.append(file_time)
            self.current_file = file_path
            if file_number is not None:
                self.processed_files = file_number
            self._file_start_time = current_time
            self._display_progress()

    def increment_processed(self):
        with self.lock:
            self.processed_files += 1

    def _display_progress(self):
        if not self.verbose or self.total_files == 0:
            return
        percentage = (self.processed_files / self.total_files) * 100
        elapsed = time.time() - self.scan_start_time if self.scan_start_time else 0
        if self.processed_files > 1 and elapsed > 0:
            if self.file_times and len(self.file_times) > 0:
                recent_times = self.file_times[-min(10, len(self.file_times)):]
                avg_time_per_file = sum(recent_times) / len(recent_times)
            else:
                avg_time_per_file = elapsed / self.processed_files
            remaining_files = self.total_files - self.processed_files
            eta = avg_time_per_file * remaining_files
            eta_str = self._format_time(eta)
        else:
            eta_str = "calculating..."
        bar_width = 30
        filled = int(bar_width * self.processed_files / self.total_files)
        bar = "█" * filled + "░" * (bar_width - filled)
        max_len = 25
        display_file = self.current_file or ""
        if len(display_file) > max_len:
            display_file = "..." + display_file[-(max_len - 3):]
        else:
            display_file = display_file.ljust(max_len)
        progress_line = (
            f"  [{bar}] {percentage:5.1f}% │ {self.processed_files:3d}/{self.total_files} │ {eta_str:10s} │ {display_file}"
        )
        sys.stdout.write("\r\033[K" + progress_line)
        sys.stdout.flush()

    def complete_phase(self, phase_name: str, summary: str = ""):
        if self.verbose:
            elapsed = time.time() - self.phase_start_time
            sys.stdout.write("\r" + " " * 80 + "\r")
            print(f"  ✓ {phase_name} completed in {self._format_time(elapsed)}")
            if summary:
                print(f"    {summary}")

    def complete_scan(self):
        if self.verbose and self.scan_start_time:
            total_time = time.time() - self.scan_start_time
            sys.stdout.write("\r" + " " * 80 + "\r")
            print("\n" + "━" * 60)
            print(f"✅ Scan completed in {self._format_time(total_time)}")
            print(f"   Processed {self.processed_files} files")
            if self.file_times:
                avg_time = sum(self.file_times) / len(self.file_times)
                print(f"   Average time per file: {self._format_time(avg_time)}")

    def _format_time(self, seconds: float) -> str:
        if seconds < 0 or seconds > 86400:
            return "calculating..."
        elif seconds < 1:
            return "< 1s"
        elif seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def log(self, message: str, level: str = "info"):
        if self.verbose:
            if self.processed_files > 0 and self.processed_files < self.total_files:
                sys.stdout.write("\r" + " " * 80 + "\r")
            prefixes = {"info": "ℹ️", "warning": "⚠️", "error": "❌", "success": "✅"}
            prefix = prefixes.get(level, "•")
            print(f"  {prefix} {message}")
            if self.processed_files > 0 and self.processed_files < self.total_files:
                self._display_progress()


